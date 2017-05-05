package libcontainerd

import (
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/grpclog"
)

const (
	pipeName      = `\\.\pipe\containerd-containerd`
	debugPipeName = `\\.\pipe\containerd-debug`
)

func (r *remote) setDefaults() {
	if r.rpcAddr == "" {
		r.rpcAddr = pipeName
	}
	if r.debugRPCAddr == "" {
		r.debugRPCAddr = debugPipeName
	}
	if r.snapshotter == "" {
		r.snapshotter = "naive" // TODO: switch to "windows" once implemented
	}
	if r.logLevel == "" {
		r.logLevel = "info"
	}
}

func (r *remote) platformCleanup() {
	// Nothing to do
}

func getGRPCConnection(addr string) (*grpc.ClientConn, error) {
	// reset the logger for grpc to log to dev/null so that it does not mess with our stdio
	grpclog.SetLogger(log.New(ioutil.Discard, "", log.LstdFlags))
	dialOpts := []grpc.DialOption{
		grpc.WithInsecure(),
		grpc.WithBackoffMaxDelay(2 * time.Second),
		grpc.WithTimeout(100 * time.Second),
	}
	dialOpts = append(dialOpts,
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return winio.DialPipe(addr, &timeout)
		},
		))

	conn, err := grpc.Dial(addr, dialOpts...)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to dial %q", addr)
	}

	return conn, nil
}
