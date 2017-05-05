// +build linux solaris

package libcontainerd

import (
	"io/ioutil"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
)

const (
	sockFile      = "docker-containerd.sock"
	debugSockFile = "docker-containerd-debug.sock"
)

func (r *remote) setDefaults() {
	if r.GRPCAddress == "" {
		r.GRPCAddress = filepath.Join(r.stateDir, sockFile)
	}
	if r.DebugAddress == "" {
		r.DebugAddress = filepath.Join(r.stateDir, debugSockFile)
	}
	if r.Snapshotter == "" {
		r.Snapshotter = "overlay"
	}
	if r.LogLevel == "" {
		r.LogLevel = "info"
	}
	if r.OOMScore == 0 {
		r.OOMScore = -999
	}
}

func (r *remote) platformCleanup() {
	os.Remove(filepath.Join(r.stateDir, sockFile))
}

func getGRPCConnection(addr string) (*grpc.ClientConn, error) {
	// reset the logger for grpc to log to dev/null so that it does not mess with our stdio
	grpclog.SetLogger(log.New(ioutil.Discard, "", log.LstdFlags))
	dialOpts := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithBackoffMaxDelay(2 * time.Second),
		grpc.WithTimeout(10 * time.Second),
	}
	dialOpts = append(dialOpts,
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", addr, timeout)
		},
		))

	conn, err := grpc.Dial(addr, dialOpts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to dial %q", addr)
	}

	return conn, nil
}
