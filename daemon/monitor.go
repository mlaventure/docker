package daemon

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/container"
	"github.com/docker/docker/libcontainerd"
	"github.com/docker/docker/restartmanager"
	"github.com/sirupsen/logrus"
)

func (daemon *Daemon) setStateCounter(c *container.Container) {
	switch c.StateString() {
	case "paused":
		stateCtr.set(c.ID, "paused")
	case "running":
		stateCtr.set(c.ID, "running")
	default:
		stateCtr.set(c.ID, "stopped")
	}
}

// StateChanged updates daemon state changes from containerd
func (daemon *Daemon) ProcessEvent(id string, e libcontainerd.EventType, ei libcontainerd.EventInfo) error {
	c, err := daemon.GetContainer(id)
	if c == nil || err != nil {
		return fmt.Errorf("no such container: %s", id)
	}

	switch e {
	case libcontainerd.EventOOM:
		// StateOOM is Linux specific and should never be hit on Windows
		if runtime.GOOS == "windows" {
			return errors.New("Received StateOOM from libcontainerd on Windows. This should never happen.")
		}
		daemon.updateHealthMonitor(c)
		if err := c.CheckpointTo(daemon.containersReplica); err != nil {
			return err
		}
		daemon.LogContainerEvent(c, "oom")
	case libcontainerd.EventExit:
		if int(ei.Pid) == c.Pid {
			_, _, err := daemon.containerd.DeleteTask(context.Background(), c.ID)
			if err != nil {
				logrus.WithError(err).Warnf("failed to delete container %s from containerd", c.ID)
			}

			c.Lock()
			c.StreamConfig.Wait()
			c.Reset(false)

			// TODO: need a way to set OOMKilled here when calling Set{Stopped,Restarting}
			// TODO: use ExitedAt from the event here, and check why it is nil
			exitStatus := container.ExitStatus{ExitCode: int(ei.ExitCode), ExitedAt: ei.ExitedAt}
			restart, wait, err := c.RestartManager().ShouldRestart(ei.ExitCode, daemon.IsShuttingDown() || c.HasBeenManuallyStopped, time.Since(c.StartedAt))
			if err == nil && restart {
				c.RestartCount++
				c.SetRestarting(&exitStatus)
			} else {
				c.SetStopped(&exitStatus)
				defer daemon.autoRemove(c)
			}

			// cancel healthcheck here, they will be automatically
			// restarted if/when the container is started again
			daemon.stopHealthchecks(c)
			attributes := map[string]string{
				"exitCode": strconv.Itoa(int(ei.ExitCode)),
			}
			daemon.LogContainerEventWithAttributes(c, "die", attributes)
			daemon.Cleanup(c)

			if err == nil && restart {
				go func() {
					err := <-wait
					if err == nil {
						// daemon.netController is initialized when daemon is restoring containers.
						// But containerStart will use daemon.netController segment.
						// So to avoid panic at startup process, here must wait util daemon restore done.
						daemon.waitForStartupDone()
						if err = daemon.containerStart(c, "", "", false); err != nil {
							logrus.Debugf("failed to restart container: %+v", err)
						}
					}
					if err != nil {
						c.SetStopped(&exitStatus)
						defer daemon.autoRemove(c)
						if err != restartmanager.ErrRestartCanceled {
							logrus.Errorf("restartmanger wait error: %+v", err)
						}
					}
				}()
			}

			daemon.setStateCounter(c)
			defer c.Unlock()
			return c.CheckpointTo(daemon.containersReplica)
		}

		if execConfig := c.ExecCommands.ByPid(int(ei.Pid)); execConfig != nil {
			ec := int(ei.ExitCode)
			execConfig.Lock()
			defer execConfig.Unlock()
			execConfig.ExitCode = &ec
			execConfig.Running = false
			execConfig.StreamConfig.Wait()
			if err := execConfig.CloseStreams(); err != nil {
				logrus.Errorf("failed to cleanup exec %s streams: %s", c.ID, err)
			}

			// remove the exec command from the container's store only and not the
			// daemon's store so that the exec command can be inspected.
			c.ExecCommands.Delete(execConfig.ID, execConfig.Pid)
		} else {
			logrus.Warnf("Ignoring Exit Event for %v no such exec command found", ei.Pid)
		}
	case libcontainerd.EventStart:
		c.Lock()
		defer c.Unlock()

		isPaused := c.Paused
		c.SetRunning(int(ei.Pid), !isPaused)
		c.HasBeenManuallyStopped = false
		c.HasBeenStartedBefore = true
		daemon.setStateCounter(c)

		if isPaused {
			daemon.updateHealthMonitor(c)
			daemon.LogContainerEvent(c, "unpause")
		} else {
			daemon.initHealthMonitor(c)
			daemon.LogContainerEvent(c, "start")
		}

		if err := c.CheckpointTo(daemon.containersReplica); err != nil {
			return err
		}

	case libcontainerd.EventPaused:
		c.Lock()
		defer c.Unlock()

		if c.Paused == false {
			c.Paused = true
			daemon.setStateCounter(c)
			daemon.updateHealthMonitor(c)
			if err := c.CheckpointTo(daemon.containersReplica); err != nil {
				return err
			}
			daemon.LogContainerEvent(c, "pause")
		}
	}
	return nil
}

func (daemon *Daemon) autoRemove(c *container.Container) {
	c.Lock()
	ar := c.HostConfig.AutoRemove
	c.Unlock()
	if !ar {
		return
	}

	var err error
	if err = daemon.ContainerRm(c.ID, &types.ContainerRmConfig{ForceRemove: true, RemoveVolume: true}); err == nil {
		return
	}
	if c := daemon.containers.Get(c.ID); c == nil {
		return
	}

	if err != nil {
		logrus.WithError(err).WithField("container", c.ID).Error("error removing container")
	}
}
