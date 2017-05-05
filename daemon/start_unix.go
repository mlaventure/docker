// +build !windows

package daemon

import (
	"github.com/docker/docker/container"
	"github.com/docker/docker/libcontainerd"
)

// getLibcontainerdCreateOptions callers must hold a lock on the container
func (daemon *Daemon) getLibcontainerdCreateOptions(container *container.Container) ([]libcontainerd.CreateOption, error) {
	createOptions := []libcontainerd.CreateOption{}

	// TODO: handle --systemd-cgroup with the container runtime
	// if UsingSystemd(daemon.configStore) {
	// 	rt.Args = append(rt.Args, "--systemd-cgroup=true")
	// }

	return createOptions, nil
}
