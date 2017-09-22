package libcontainerd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd"
	"github.com/docker/docker/pkg/idtools"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func (c *client) UpdateResources(ctx context.Context, containerID string, resources *Resources) error {
	p, err := c.getProcess(containerID, InitProcessName)
	if err != nil {
		return err
	}

	// go doesn't like the alias in 1.8, this means this need to be
	// platform specific
	return p.(containerd.Task).Update(ctx, containerd.WithResources((*specs.LinuxResources)(resources)))
}

func hostIDFromMap(id uint32, mp []specs.LinuxIDMapping) int {
	for _, m := range mp {
		if id >= m.ContainerID && id <= m.ContainerID+m.Size-1 {
			return int(m.HostID + id - m.ContainerID)
		}
	}
	return 0
}

func prepareBundleDir(bundleDir string, ociSpec *specs.Spec) (string, error) {
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
		return bundleDir, idtools.MkdirAllAndChownNew(bundleDir, 0755, idtools.IDPair{0, 0})
	}

	p := string(filepath.Separator)
	components := strings.Split(bundleDir, string(filepath.Separator))
	for _, d := range components[1 : len(components)-1] {
		p = filepath.Join(p, d)
		fi, err := os.Stat(p)
		if err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if os.IsNotExist(err) || fi.Mode()&1 == 0 {
			p = fmt.Sprintf("%s.%d.%d", p, uid, gid)
			if err := idtools.MkdirAs(p, 0700, uid, gid); err != nil && !os.IsExist(err) {
				return "", err
			}
		}
	}
	// Create the last directory (i.e. the container id)
	err := idtools.MkdirAs(components[len(components)-1:][0], 0700, uid, gid)
	if err != nil && !os.IsExist(err) {
		return "", err
	}

	return p, nil
}

func newFIFOSet(bundleDir, containerID, processID string, withStdin, withTerminal bool) *containerd.FIFOSet {
	fifos := &containerd.FIFOSet{
		Terminal: withTerminal,
		Out:      filepath.Join(bundleDir, processID+"-stdout"),
	}

	if withStdin {
		fifos.In = filepath.Join(bundleDir, processID+"-stdin")
	}

	if !fifos.Terminal {
		fifos.Err = filepath.Join(bundleDir, processID+"-stderr")
	}

	return fifos
}
