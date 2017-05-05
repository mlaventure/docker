// +build linux solaris

package libcontainerd

import (
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"

	"github.com/docker/docker/pkg/ioutils"
	"github.com/pkg/errors"
	"github.com/tonistiigi/fifo"
	"golang.org/x/net/context"
	"golang.org/x/sys/unix"
)

func newProcess(ctx context.Context, id, rootDir string, withStdin, terminal bool) (p *process, err error) {
	p = &process{
		id:   id,
		io:   &IOPipe{},
		root: rootDir,
	}
	defer func() {
		if err != nil {
			p.Cleanup()
		}
	}()

	if withStdin {
		p.io.Stdin, err = fifo.OpenFifo(ctx, p.pipeName(unix.Stdin), unix.O_WRONLY|unix.O_CREAT|unix.O_NONBLOCK, 0700)
		if err != nil {
			return
		}
	}

	p.io.Stdout, err = fifo.OpenFifo(ctx, p.pipeName(unix.Stdout), unix.O_RDONLY|unix.O_CREAT|unix.O_NONBLOCK, 0700)
	if err != nil {
		return nil, err
	}

	if goruntime.GOOS == "solaris" || !terminal {
		// For Solaris terminal handling is done exclusively by the runtime therefore we make no distinction
		// in the processing for terminal and !terminal cases.
		p.io.Stderr, err = fifo.OpenFifo(ctx, p.pipeName(unix.Stderr), unix.O_RDONLY|unix.O_CREAT|unix.O_NONBLOCK, 0700)
		if err != nil {
			return nil, err
		}
	}

	return
}

var fdNames = map[int]string{
	unix.Stdin:  "stdin",
	unix.Stdout: "stdout",
	unix.Stderr: "stderr",
}

func (p *process) pipeName(index int) string {
	return filepath.Join(p.root, p.id+"-"+fdNames[index])
}

func (p *process) IOPaths() (string, string, string) {
	var (
		stdin  = p.pipeName(unix.Stdin)
		stdout = p.pipeName(unix.Stdout)
		stderr = p.pipeName(unix.Stderr)
	)
	// TODO: debug why we're having zombies when I don't unset those
	if p.io.Stdin == nil {
		stdin = ""
	}
	if p.io.Stderr == nil {
		stderr = ""
	}
	return stdin, stdout, stderr
}

func (p *process) Cleanup() error {
	var retErr error

	// Ensure everything was closed
	p.CloseIO()

	for _, i := range [3]string{
		p.pipeName(unix.Stdin),
		p.pipeName(unix.Stdout),
		p.pipeName(unix.Stderr),
	} {
		err := os.Remove(i)
		if err != nil {
			if retErr == nil {
				retErr = errors.Wrapf(err, "failed to remove %s", i)
			} else {
				retErr = errors.Wrapf(retErr, "failed to remove %s", i)
			}
		}
	}

	return retErr
}

func newReadOnlyFifo(ctx context.Context, name string) (io.ReadCloser, error) {
	pipe, err := fifo.OpenFifo(ctx, name, unix.O_RDONLY|unix.O_CREAT|unix.O_NONBLOCK, 0700)
	if err != nil {
		return nil, err
	}
	rc := ioutils.NewReadCloserWrapper(pipe, func() error {
		pipe.Close()
		if err := os.Remove(name); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	})
	return rc, nil
}
