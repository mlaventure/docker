// +build !windows

package daemon

import (
	"fmt"
	"path/filepath"

	"github.com/containerd/containerd/linux/runcopts"
	"github.com/docker/docker/container"
	"github.com/pkg/errors"
)

// getLibcontainerdCreateOptions callers must hold a lock on the container
func (daemon *Daemon) getLibcontainerdCreateOptions(container *container.Container) (interface{}, error) {
	// Ensure a runtime has been assigned to this container
	if container.HostConfig.Runtime == "" {
		container.HostConfig.Runtime = daemon.configStore.GetDefaultRuntimeName()
		container.CheckpointTo(daemon.containersReplica)
	}

	rt := daemon.configStore.GetRuntime(container.HostConfig.Runtime)
	if rt == nil {
		return nil, validationError{errors.Errorf("no such runtime '%s'", container.HostConfig.Runtime)}
	}
	// TODO(mlaventure): create a script shell to take in account the possible
	// runtime-args
	opts := &runcopts.RuncOptions{
		Runtime: rt.Path,
		RuntimeRoot: filepath.Join(daemon.configStore.ExecRoot,
			fmt.Sprintf("runtime-%s", container.HostConfig.Runtime)),
	}

	if UsingSystemd(daemon.configStore) {
		opts.SystemdCgroup = true
	}

	return opts, nil
}
