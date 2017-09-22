package libcontainerd

import (
	"fmt"

	"github.com/containerd/containerd"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func prepareBundleDir(bundleDir string, ociSpec *specs.Spec) (string, error) {
	return bundleDir, nil
}

func pipeName(containerID, processID, name string) string {
	return fmt.Sprintf(`\\.\pipe\containerd-%s-%s-%s`, containerID, processID, name)
}

func newFIFOSet(bundleDir, containerID, processID string, withStdin, withTerminal bool) *containerd.FIFOSet {
	fifos := &containerd.FIFOSet{
		Terminal: withTerminal,
		Out:      pipeName(containerID, processID, "stdout"),
	}

	if withStdin {
		fifos.In = pipeName(containerID, processID, "stdin")
	}

	if !fifos.Terminal {
		fifos.Err = pipeName(containerID, processID, "stderr")
	}

	return fifos
}
