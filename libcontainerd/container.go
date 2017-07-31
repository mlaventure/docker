package libcontainerd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/api/types/task"
	"github.com/containerd/containerd/namespaces"
	"github.com/docker/docker/pkg/ioutils"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	// InitProcessName is the name given in the lookup map of processes
	// for the first process started in a container.
	InitProcessName = "init"
	configFilename  = "config.json"
)

type container struct {
	sync.RWMutex

	client         *client
	id             string
	bundleDir      string
	ociSpec        *specs.Spec
	initProcess    *process
	processes      map[string]*process
	processesByPid map[uint32]*process
}

func newContainer(c *client, rootDir, id string) (*container, error) {
	root, err := filepath.Abs(rootDir)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to retrieve absolute path for %s", rootDir)
	}

	return &container{
		client:         c,
		id:             id,
		bundleDir:      filepath.Join(root, id),
		processes:      make(map[string]*process),
		processesByPid: make(map[uint32]*process),
	}, nil
}

func (c *container) ID() string {
	return c.id
}

func (c *container) Restore(ctx context.Context, withStdin, withTerminal bool, attachStdio StdioCallback) (alive bool, pid int, err error) {
	// TODO: get the container template
	// TODO: make a getOCISpec platform method to extract the oci specs

	ci, err := c.client.remote.tasksSvc.Get(ctx, &tasksapi.GetTaskRequest{ContainerID: c.id}, grpc.FailFast(false))
	if err != nil {
		errDesc := grpc.ErrorDesc(err)
		return false, -1, errors.Wrapf(fmt.Errorf(errDesc), "failed to retrieve container %s info", c.id)
	}

	// TODO(mlaventure): add support to restore all processes not just the init one
	// (e.g. make a directory per process for the IO in the unix case)

	p, err := newProcess(ctx, InitProcessName, c.bundleDir, withStdin, withTerminal)
	if err != nil {
		return false, -1, err
	}
	defer func() {
		if err != nil {
			// Only close ios here, we don't want to remove the actual
			// underlying pipe/fifo used by the implementation until the
			// container is closed
			p.CloseIO()
		}
	}()
	p.SetPid(ci.Task.Pid)
	c.initProcess = p
	c.processes[InitProcessName] = p
	c.processesByPid[ci.Task.Pid] = p

	if ci.Task.Status == task.StatusStopped {
		return false, int(ci.Task.Pid), nil
	}

	err = c.attachProcessStdio(p, attachStdio)
	if err != nil {
		return true, -1, err
	}

	return true, int(ci.Task.Pid), nil
}

func (c *container) Create(ctx context.Context, ociSpec *specs.Spec, options ...CreateOption) (err error) {
	if err = c.prepareBundleDir(ociSpec); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(c.bundleDir)
		}
	}()

	cr, err := newContainerCreateRequest(c.id, ociSpec, options...)
	if err != nil {
		return err
	}

	_, err = c.client.remote.containersSvc.Create(ctx, cr)
	if err != nil {
		return errors.Errorf("failed to create container: " + grpc.ErrorDesc(err))
	}

	c.ociSpec = ociSpec

	return nil
}

func (c *container) CreateTask(ctx context.Context, withStdin bool, attachStdio StdioCallback) (pid int, err error) {
	// We don't use initProcess here, because we can't nil it on delete
	// since we use it in ProcessEvent()
	if len(c.processes) != 0 {
		return -1, errors.Errorf("container %s task has already been created", c.id)
	}

	p, err := newProcess(ctx, InitProcessName, c.bundleDir, withStdin, c.ociSpec.Process.Terminal)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			p.Cleanup()
		}
	}()

	cr := &tasksapi.CreateTaskRequest{
		ContainerID: c.id,
		Terminal:    c.ociSpec.Process.Terminal,
	}

	cr.Stdin, cr.Stdout, cr.Stderr = p.IOPaths()
	resp, err := c.client.remote.tasksSvc.Create(ctx, cr)
	if err != nil {
		err = errors.New(grpc.ErrorDesc(err))
		return
	}
	p.SetPid(resp.Pid)

	err = c.attachProcessStdio(p, attachStdio)
	if err != nil {
		return
	}

	c.initProcess = p
	c.processes[InitProcessName] = p
	c.processesByPid[resp.Pid] = p
	return int(resp.Pid), nil
}

func (c *container) Start(ctx context.Context) error {
	_, err := c.client.remote.tasksSvc.Start(ctx, &tasksapi.StartTaskRequest{ContainerID: c.id})
	if err != nil {
		err = errors.New(grpc.ErrorDesc(err))
	}
	return err
}

func (c *container) Exec(ctx context.Context, id string, spec *specs.Process, withStdin bool, attachStdio StdioCallback) (int, error) {
	_, err := c.getProcess(id)
	if err == nil {
		return -1, errors.Errorf("container %s already has a process with id %s", c.id, id)
	}

	er, err := newExecRequest(c.ID(), spec)
	if err != nil {
		return -1, err
	}

	p, err := newProcess(ctx, id, c.bundleDir, withStdin, spec.Terminal)
	if err != nil {
		return -1, err
	}

	er.Stdin, er.Stdout, er.Stderr = p.IOPaths()

	resp, err := c.client.remote.tasksSvc.Exec(ctx, er)
	if err != nil {
		p.Cleanup()
		return -1, errors.New(grpc.ErrorDesc(err))

	}
	p.SetPid(resp.Pid)
	c.storeProcess(p)

	err = c.attachProcessStdio(p, attachStdio)
	if err != nil {
		go func() {
			err := c.SignalProcess(context.Background(), id, int(syscall.SIGKILL))
			if err != nil {
				logrus.WithField("container", c.ID).
					Errorf("failed to kill exec %s (pid: %d) after failed stdio attach", id, resp.Pid)
			}
			c.removeProcess(id)
		}()
		return -1, err
	}

	return int(resp.Pid), nil
}

func (c *container) SignalProcess(ctx context.Context, processID string, signal int) error {
	p, err := c.getProcess(processID)
	if err != nil {
		return err
	}

	kr := &tasksapi.KillRequest{
		ContainerID: c.id,
		Signal:      uint32(signal),
		All:         p.Pid() == c.initProcess.Pid(),
	}
	if processID == InitProcessName {
		kr.ExecID = c.id
	} else {
		kr.ExecID = processID
	}

	_, err = c.client.remote.tasksSvc.Kill(ctx, kr)
	if err != nil {
		err = errors.New(grpc.ErrorDesc(err))
	}
	return err
}

func (c *container) ResizeTerminal(ctx context.Context, id string, width, height int) error {
	_, err := c.getProcess(id)
	if err != nil {
		return err
	}

	if id == InitProcessName {
		id = c.id
	}

	_, err = c.client.remote.tasksSvc.ResizePty(ctx, &tasksapi.ResizePtyRequest{
		ContainerID: c.id,
		ExecID:      id,
		Width:       uint32(width),
		Height:      uint32(height),
	})

	if err != nil {
		err = errors.New(grpc.ErrorDesc(err))
	}
	return err
}

func (c *container) CloseStdin(ctx context.Context, id string) error {
	_, err := c.getProcess(id)
	if err != nil {
		return err
	}

	if id == InitProcessName {
		id = c.id
	}

	_, err = c.client.remote.tasksSvc.CloseIO(ctx, &tasksapi.CloseIORequest{
		ContainerID: c.id,
		ExecID:      id,
		Stdin:       true,
	})

	if err != nil {
		err = errors.New(grpc.ErrorDesc(err))
	}
	return err
}

func (c *container) Pause(ctx context.Context) error {
	_, err := c.client.remote.tasksSvc.Pause(ctx, &tasksapi.PauseTaskRequest{c.id})
	if err != nil {
		err = errors.New(grpc.ErrorDesc(err))
	}
	return err
}

func (c *container) Resume(ctx context.Context) error {
	_, err := c.client.remote.tasksSvc.Resume(ctx, &tasksapi.ResumeTaskRequest{c.id})
	if err != nil {
		err = errors.New(grpc.ErrorDesc(err))
	}
	return err
}

type statsNotImpl struct {
	error
}

func (s statsNotImpl) ContainerIsRunning() bool {
	return false
}

func (c *container) Stats(ctx context.Context) (*Stats, error) {
	return nil, statsNotImpl{errors.New("Stats() is not implemented")}
}

func (c *container) ListPids(ctx context.Context) ([]uint32, error) {
	resp, err := c.client.remote.tasksSvc.ListPids(ctx, &tasksapi.ListPidsRequest{c.id})
	if err != nil {
		return nil, errors.New(grpc.ErrorDesc(err))
	}

	pids := make([]uint32, len(resp.Pids))
	for _, p := range resp.Pids {
		pids = append(pids, p)
	}

	return pids, nil
}

func (c *container) DeleteTask(ctx context.Context) (ec uint32, et time.Time, err error) {
	dr, err := c.client.remote.tasksSvc.Delete(ctx, &tasksapi.DeleteTaskRequest{ContainerID: c.id})
	if err != nil {
		err = errors.New(grpc.ErrorDesc(err))
		return
	}

	c.Lock()
	for id, p := range c.processes {
		p.Cleanup()
		delete(c.processes, id)
		delete(c.processesByPid, p.Pid())
	}
	c.Unlock()

	ec = dr.ExitStatus
	et = dr.ExitedAt

	return
}

func (c *container) Delete(ctx context.Context) error {
	err := os.RemoveAll(c.bundleDir)

	_, err = c.client.remote.containersSvc.Delete(ctx, &containersapi.DeleteContainerRequest{ID: c.id})
	if err != nil {
		err = errors.New(grpc.ErrorDesc(err))
	}
	return err
}

func (c *container) ProcessEvent(et EventType, ei EventInfo) {
	c.client.eventQ.append(c.id, func() {
		err := c.client.backend.ProcessEvent(c.id, et, ei)
		if err != nil {
			logrus.WithError(err).WithField("container", c.id).Errorf("libcontainerd: failed to process event %v: %#v", et, ei)
		}

		if et == EventExit && ei.ProcessID != c.id {
			_, err := c.client.remote.tasksSvc.DeleteProcess(context.Background(),
				&tasksapi.DeleteProcessRequest{ContainerID: c.id, ExecID: ei.ProcessID})
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"error":      grpc.ErrorDesc(err),
					"container":  c.id,
					"process-id": ei.ProcessID,
				}).Warn("failed to delete process")
			}
			c.removeProcess(ei.ProcessID)
		}
	})
}

func (c *container) storeProcess(p *process) {
	c.Lock()
	c.processes[p.ID()] = p
	c.Unlock()
}

func (c *container) removeProcess(id string) {
	c.Lock()
	p, ok := c.processes[id]
	if ok {
		delete(c.processes, id)
		delete(c.processesByPid, p.Pid())
	}
	c.Unlock()
}

func (c *container) removeProcessByPid(pid uint32) {
	c.Lock()
	p, ok := c.processesByPid[pid]
	if ok {
		delete(c.processes, p.ID())
		delete(c.processesByPid, pid)
	}
	c.Unlock()
}

func (c *container) getProcess(id string) (*process, error) {
	c.RLock()
	c.RUnlock()
	p, ok := c.processes[id]
	if !ok {
		return nil, fmt.Errorf("no such process: %s", id)
	}
	return p, nil
}

func (c *container) attachProcessStdio(p *process, attachStdio StdioCallback) error {
	iop := *p.IOPipe()
	if iop.Stdin != nil {
		var (
			err       error
			stdinOnce sync.Once
			execID    = p.ID()
		)
		pipe := iop.Stdin
		iop.Stdin = ioutils.NewWriteCloserWrapper(pipe, func() error {
			stdinOnce.Do(func() {
				pipe.Close()
				ctx := namespaces.WithNamespace(context.Background(), c.client.namespace)
				_, err = c.client.remote.tasksSvc.CloseIO(ctx, &tasksapi.CloseIORequest{
					ContainerID: c.id,
					ExecID:      execID,
					Stdin:       true,
				})
				if strings.Contains(grpc.ErrorDesc(err), "container does not exist") {
					err = nil
				}
			})
			if err != nil {
				err = errors.New(grpc.ErrorDesc(err))
			}
			return err
		})
	}
	return attachStdio(iop)
}
