// +build linux solaris

package libcontainerd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	tasksapi "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/plugin"
	"github.com/docker/docker/pkg/idtools"
	protobuf "github.com/gogo/protobuf/types"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

func newContainerCreateRequest(id string, ociSpec *specs.Spec, options ...CreateOption) (*containersapi.CreateContainerRequest, error) {
	spec, err := json.Marshal(ociSpec)
	if err != nil {
		return nil, errors.Wrapf(err, "libcontainerd: failed to marshal OCI spec for container %s", id)
	}

	cr := &containersapi.CreateContainerRequest{
		Container: containersapi.Container{
			ID: id,
			Spec: &protobuf.Any{
				TypeUrl: specs.Version,
				Value:   spec,
			},
			Runtime: &containersapi.Container_Runtime{
				Name: fmt.Sprintf("%s.%s", plugin.RuntimePlugin, runtime.GOOS),
			},
		},
	}

	for _, opt := range options {
		if err := opt.Apply(cr); err != nil {
			return nil, err
		}
	}

	return cr, nil
}

func newExecRequest(id string, ociSpec *specs.Process) (*tasksapi.ExecProcessRequest, error) {
	spec, err := json.Marshal(ociSpec)
	if err != nil {
		return nil, errors.Wrapf(err, "libcontainerd: failed to marshal OCI spec for container %s", id)
	}

	return &tasksapi.ExecProcessRequest{
		ContainerID: id,
		Spec: &protobuf.Any{
			TypeUrl: specs.Version,
			Value:   spec,
		},
		Terminal: ociSpec.Terminal,
	}, nil
}

func hostIDFromMap(id uint32, mp []specs.LinuxIDMapping) int {
	for _, m := range mp {
		if id >= m.ContainerID && id <= m.ContainerID+m.Size-1 {
			return int(m.HostID + id - m.ContainerID)
		}
	}
	return 0
}

func getRootIDs(s specs.Spec) (int, int) {
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == specs.UserNamespace {
			return hostIDFromMap(0, s.Linux.UIDMappings), hostIDFromMap(0, s.Linux.GIDMappings)
		}
	}
	return 0, 0
}

func (c *container) prepareBundleDir(ociSpec *specs.Spec) error {
	var (
		uid int
		gid int
	)

	for _, ns := range ociSpec.Linux.Namespaces {
		if ns.Type == specs.UserNamespace {
			uid = hostIDFromMap(0, ociSpec.Linux.UIDMappings)
			gid = hostIDFromMap(0, ociSpec.Linux.GIDMappings)
			break
		}
	}
	if uid == 0 && gid == 0 {
		return idtools.MkdirAllAndChownNew(c.bundleDir, 0755, idtools.IDPair{0, 0})
	}

	p := string(filepath.Separator)
	components := strings.Split(c.bundleDir, string(filepath.Separator))
	for _, d := range components[1 : len(components)-1] {
		p = filepath.Join(p, d)
		fi, err := os.Stat(p)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if os.IsNotExist(err) || fi.Mode()&1 == 0 {
			p = fmt.Sprintf("%s.%d.%d", p, uid, gid)
			if err := idtools.MkdirAs(p, 0700, uid, gid); err != nil && !os.IsExist(err) {
				return err
			}
		}
	}
	// Create the last directory (i.e. the container id)
	if err := idtools.MkdirAs(components[len(components)-1:][0], 0700, uid, gid); err != nil && !os.IsExist(err) {
		return err
	}

	c.bundleDir = p
	return nil
}
