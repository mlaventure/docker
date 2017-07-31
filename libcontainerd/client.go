package libcontainerd

import (
	"context"
	"sync"
	"time"

	"github.com/containerd/containerd/namespaces"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// clientCommon contains the platform agnostic fields used in the client structure
type client struct {
	sync.RWMutex // protects containers map

	remote *remote

	namespace  string
	backend    Backend
	eventQ     queue
	containers map[string]*container
	//	locker     *locker.Locker // TODO: may not be needed
}

func (c *client) Restore(ctx context.Context, id string, withStdin, withTerminal bool, attachStdio StdioCallback) (bool, int, error) {
	c.Lock()
	defer c.Unlock()

	ctr, err := newContainer(c, c.remote.stateDir, id)
	if err != nil {
		return false, -1, err
	}

	ctx = namespaces.WithNamespace(ctx, c.namespace)
	alive, pid, err := ctr.Restore(ctx, withStdin, withTerminal, attachStdio)
	if err != nil {
		return false, -1, err
	}

	if alive {
		// we already have the lock
		c.containers[id] = ctr
	}

	return false, pid, nil
}

func (c *client) Create(ctx context.Context, id string, ociSpec *specs.Spec, options ...CreateOption) error {
	ctx, _, err := c.getContainer(ctx, id)
	if err == nil {
		return errors.Errorf("container id %s is already in use", id)
	}

	ctr, err := newContainer(c, c.remote.stateDir, id)
	if err != nil {
		return err
	}

	err = ctr.Create(ctx, ociSpec, options...)
	if err != nil {
		return err
	}

	c.storeContainer(ctr)

	return nil
}

// Start create and start a task for the specified containerd id
func (c *client) Start(ctx context.Context, containerID string, withStdin bool, attachStdio StdioCallback) (int, error) {
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return -1, err
	}

	pid, err := ctr.CreateTask(ctx, withStdin, attachStdio)
	if err != nil {
		logrus.Debugf("CreateTask failed: %v", err)
		return -1, err
	}

	if err = ctr.Start(ctx); err != nil {
		logrus.Debugf("client.Start failed: %v", err)
		if _, _, err := ctr.DeleteTask(ctx); err != nil {
			logrus.Debugf("DeleteTask failed: %v", err)
			logrus.WithError(err).Errorf("libcontainerd: failed to delete container %s task", containerID)
		}
		return -1, err
	}

	return pid, err
}

func (c *client) Exec(ctx context.Context, containerID, processID string, spec *specs.Process, withStdin bool, attachStdio StdioCallback) (int, error) {
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return -1, err
	}

	return ctr.Exec(ctx, processID, spec, withStdin, attachStdio)
}

func (c *client) SignalProcess(ctx context.Context, containerID, processID string, signal int) error {
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return err
	}

	return ctr.SignalProcess(ctx, processID, signal)
}

func (c *client) ResizeTerminal(ctx context.Context, containerID, processID string, width, height int) error {
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return err
	}
	return ctr.ResizeTerminal(ctx, processID, width, height)
}

func (c *client) CloseStdin(ctx context.Context, containerID, processID string) error {
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return err
	}
	return ctr.CloseStdin(ctx, processID)
}

func (c *client) Pause(ctx context.Context, containerID string) error {
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return err
	}

	return ctr.Pause(ctx)
}

func (c *client) Resume(ctx context.Context, containerID string) error {
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return err
	}

	return ctr.Resume(ctx)
}

func (c *client) Stats(ctx context.Context, containerID string) (*Stats, error) {
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return nil, err
	}

	return ctr.Stats(ctx)
}

func (c *client) ListPids(ctx context.Context, containerID string) ([]uint32, error) {
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return nil, err
	}

	return ctr.ListPids(ctx)
}

func (c *client) DeleteTask(ctx context.Context, containerID string) (uint32, time.Time, error) {
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return 255, time.Time{}, err
	}

	ec, exitedAt, err := ctr.DeleteTask(ctx)
	if err != nil {
		return ec, exitedAt, err
	}

	return ec, exitedAt, err
}

func (c *client) Delete(ctx context.Context, containerID string) error {
	logrus.Debugf("libcontainerd: calling Delete on %s", containerID)
	ctx, ctr, err := c.getContainer(ctx, containerID)
	if err != nil {
		return err
	}

	err = ctr.Delete(ctx)
	if err != nil {
		return err
	}

	c.removeContainer(containerID)

	return nil
}

func (c *client) UpdateResources(ctx context.Context, containerID string, resources Resources) error {
	_, _, err := c.getContainer(ctx, containerID)
	if err != nil {
		return err
	}

	return errors.New("UpdateResources() is not implemented")
}

func (c *client) CreateCheckpoint(ctx context.Context, containerID string, checkpointID string, checkpointDir string, exit bool) error {
	_, _, err := c.getContainer(ctx, containerID)
	if err != nil {
		return err
	}

	return errors.New("CreateCheckpoint() is not implemented")
}

func (c *client) DeleteCheckpoint(ctx context.Context, containerID string, checkpointID string, checkpointDir string) error {
	_, _, err := c.getContainer(ctx, containerID)
	if err != nil {
		return err
	}

	return errors.New("DeleteCheckpoint() is not implemented")
}

func (c *client) ListCheckpoints(ctx context.Context, containerID string, checkpointDir string) (*Checkpoints, error) {
	_, _, err := c.getContainer(ctx, containerID)
	if err != nil {
		return nil, err
	}

	return nil, errors.New("ListCheckpoints() is not implemented")
}

func (c *client) GetServerVersion(ctx context.Context) (*ServerVersion, error) {
	return nil, errors.New("GetServerVersion() is not implemented")
}

func (c *client) storeContainer(ctr *container) {
	c.Lock()
	c.containers[ctr.ID()] = ctr
	c.Unlock()
}

func (c *client) getContainer(ctx context.Context, id string) (context.Context, *container, error) {
	c.RLock()
	c.RUnlock()
	ctx = namespaces.WithNamespace(ctx, c.namespace)
	ctr, ok := c.containers[id]
	if !ok {
		return ctx, nil, errors.Errorf("no such container: %s", id)
	}
	return ctx, ctr, nil
}

func (c *client) removeContainer(id string) {
	c.Lock()
	delete(c.containers, id)
	c.Unlock()
}

// func (clnt *client) lock(containerID string) {
// 	clnt.locker.Lock(containerID)
// }

// func (clnt *client) unlock(containerID string) {
// 	clnt.locker.Unlock(containerID)
// }
