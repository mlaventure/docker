// +build linux solaris

package libcontainerd

import (
	"fmt"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	"github.com/containerd/containerd/plugin"
)

// WithOOMScore defines the oom_score_adj to set for the containerd process.
func WithOOMScore(score int) RemoteOption {
	return oomScore(score)
}

type oomScore int

func (o oomScore) Apply(r Remote) error {
	if remote, ok := r.(*remote); ok {
		remote.OOMScore = int(o)
		return nil
	}
	return fmt.Errorf("WithOOMScore option not supported for this remote")
}

// WithSubreaper sets whether containerd should register itself as a
// subreaper
func WithSubreaper(reap bool) RemoteOption {
	return subreaper(reap)
}

type subreaper bool

func (s subreaper) Apply(r Remote) error {
	if remote, ok := r.(*remote); ok {
		remote.AsSubreaper = bool(s)
		return nil
	}
	return fmt.Errorf("WithSubreaper option not supported for this remote")
}

// CreateOption allows to configure parameters of container creation.
type CreateOption interface {
	Apply(*containersapi.CreateContainerRequest) error
}

func WithRuntime(name string) CreateOption {
	return containerRuntime(name)
}

type containerRuntime string

func (r containerRuntime) Apply(cr *containersapi.CreateContainerRequest) error {
	cr.Container.Runtime.Name = fmt.Sprintf("%s.%s", plugin.RuntimePlugin, string(r))
	return nil
}
