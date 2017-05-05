package libcontainerd

import (
	"context"
	"io"
	"time"

	"github.com/opencontainers/runtime-spec/specs-go"
)

type EventType string

// State constants used in state change reporting.
const (
	EventUnknown   EventType = "unknown"
	EventExit      EventType = "exit"
	EventOOM       EventType = "oom"
	EventCreate    EventType = "create"
	EventStart     EventType = "start"
	EventExecAdded EventType = "exec-added"
	EventPaused    EventType = "pause"
)

// Remote on Linux defines the accesspoint to the containerd grpc API.
// Remote on Windows is largely an unimplemented interface as there is
// no remote containerd.
type Remote interface {
	// Client returns a new Client instance connected with given Backend.
	NewClient(namespace string, b Backend) (Client, error)
	// Cleanup stops containerd if it was started by libcontainerd.
	// Note this is not used on Windows as there is no remote containerd.
	Cleanup()
	// UpdateOptions allows various remote options to be updated at runtime.
	UpdateOptions(...RemoteOption) error
}

// RemoteOption allows to configure parameters of remotes.
// This is unused on Windows.
type RemoteOption interface {
	Apply(Remote) error
}

// EventInfo contains the event info
type EventInfo struct {
	Pid      uint32
	ExitCode uint32
	ExitedAt time.Time
}

// Backend defines callbacks that the client of the library needs to implement.
type Backend interface {
	ProcessEvent(containerID string, event EventType, ei EventInfo) error
}

// Client provides access to containerd features.
type Client interface {
	GetServerVersion(ctx context.Context) (*ServerVersion, error)

	Restore(ctx context.Context, containerID string, withStdin, withTerminal bool, attachStdio StdioCallback) (alive bool, pid int, err error)

	Create(ctx context.Context, containerID string, spec *specs.Spec, options ...CreateOption) error
	Start(ctx context.Context, containerID string, withStdin bool, attachStdio StdioCallback) (pid int, err error)
	SignalProcess(ctx context.Context, containerID, processID string, signal int) error
	Exec(ctx context.Context, containerID, processID string, spec *specs.Process, withStdin bool, attachStdio StdioCallback) (int, error)
	ResizeTerminal(ctx context.Context, containerID, processID string, width, height int) error
	CloseStdin(ctx context.Context, containerID, processID string) error
	Pause(ctx context.Context, containerID string) error
	Resume(ctx context.Context, containerID string) error
	Stats(ctx context.Context, containerID string) (*Stats, error)
	ListPids(ctx context.Context, containerID string) ([]uint32, error)
	DeleteTask(ctx context.Context, containerID string) (uint32, time.Time, error)
	Delete(ctx context.Context, containerID string) error

	UpdateResources(ctx context.Context, containerID string, resources Resources) error
	CreateCheckpoint(ctx context.Context, containerID string, checkpointID string, checkpointDir string, exit bool) error
	DeleteCheckpoint(ctx context.Context, containerID string, checkpointID string, checkpointDir string) error
	ListCheckpoints(ctx context.Context, containerID string, checkpointDir string) (*Checkpoints, error)
}

// StdioCallback is called to connect a container or process stdio.
type StdioCallback func(IOPipe) error

// IOPipe contains the stdio streams.
type IOPipe struct {
	Stdin    io.WriteCloser
	Stdout   io.ReadCloser
	Stderr   io.ReadCloser
	Terminal bool // Whether stderr is connected on Windows
}

// ServerVersion contains version information as retrieved from the
// server
type ServerVersion struct {
}

// ProcessCommon contains information about a running process within a container
type ProcessCommon struct {
	Pid        uint32
	Args       []string
	Env        []string
	User       *specs.User
	Cwd        string
	Terminal   bool
	ExitStatus uint32
	Status     int32
	Stdin      string
	Stdout     string
	Stderr     string
}
