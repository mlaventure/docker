package libcontainerd

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"

	"github.com/Sirupsen/logrus"
	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	"github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/namespaces"
	"github.com/docker/docker/pkg/system"
	"github.com/gogo/protobuf/proto"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

const (
	maxConnectionRetryCount = 3
	healthCheckTimeout      = 3 * time.Second
	shutdownTimeout         = 15 * time.Second
	configFile              = "containerd.toml"
	binaryName              = "docker-containerd"
	pidFile                 = "docker-containerd.pid"

	configTemplate = `
state = "{{ .StateDir }}"
root = "{{ .RootDir }}"
snapshotter = "{{ .Snapshotter }}"
subreaper = {{ .AsSubreaper }}
oom_score = {{ .OOMScore }}

[grpc]
  address = "{{ .GRPCAddress }}"
  uid = {{ .GRPCUid }}
  gid = {{ .GRPCGid }}

[debug]
  address = "{{ .DebugAddress }}"
  level = "{{ .LogLevel }}"

[metrics]
  address = "{{ .MetricsAddress }}"

{{ range $name, $conf := .PluginConfs -}}
[plugins.{{ $name }}]
  {{ range $k, $v := $conf.Conf -}}
  {{ $k }} = {{ $v }}
  {{ end }}
{{ end -}}
`
)

type containerdPluginConfig struct {
	// Conf holds a map of options for the config. The value is used
	// verbatim, so if the ouput needs to be quoted, the quotes should be
	// part of it.
	Conf map[string]string
}

type containerdConfig struct {
	StateDir    string
	RootDir     string
	Snapshotter string
	OOMScore    int
	AsSubreaper bool

	GRPCAddress string
	GRPCUid     int
	GRPCGid     int

	DebugAddress string
	LogLevel     string

	MetricsAddress string

	PluginConfs map[string]containerdPluginConfig
}

type remote struct {
	sync.RWMutex

	rpcConn       *grpc.ClientConn
	containersSvc containersapi.ContainersClient
	tasksSvc      tasks.TasksClient
	eventsSvc     eventsapi.EventsClient
	daemonPid     int

	daemonWaitCh chan struct{}
	clients      []*client
	shutdown     bool

	// Options
	startDaemon bool
	rootDir     string
	stateDir    string

	containerdConfig
}

// New creates a fresh instance of libcontainerd remote.
func New(rootDir, stateDir string, options ...RemoteOption) (rem Remote, err error) {
	defer func() {
		if err != nil {
			err = errors.Wrap(err, "Failed to connect to containerd. "+
				"Please make sure containerd is installed in your PATH or that you have specified the correct address.")
		}
	}()

	r := &remote{
		rootDir:  rootDir,
		stateDir: stateDir,
		containerdConfig: containerdConfig{
			RootDir:     rootDir,
			StateDir:    stateDir,
			PluginConfs: make(map[string]containerdPluginConfig),
		},
		daemonPid: -1,
	}
	rem = r
	for _, option := range options {
		if err = option.Apply(r); err != nil {
			return
		}
	}
	r.setDefaults()

	if err = system.MkdirAll(stateDir, 0700, ""); err != nil {
		return
	}

	if r.startDaemon {
		if err = r.startContainerd(); err != nil {
			return
		}
	}
	r.rpcConn, err = getGRPCConnection(r.GRPCAddress)
	if err != nil {
		r.Cleanup()
		return nil, err
	}
	r.containersSvc = containersapi.NewContainersClient(r.rpcConn)
	r.tasksSvc = tasks.NewTasksClient(r.rpcConn)
	r.eventsSvc = eventsapi.NewEventsClient(r.rpcConn)

	go r.monitorConnection()

	return r, nil
}

func (r *remote) NewClient(ns string, b Backend) (Client, error) {
	c := &client{
		namespace:  ns,
		remote:     r,
		backend:    b,
		containers: make(map[string]*container),
	}

	go r.processEventStream(c)

	r.Lock()
	r.clients = append(r.clients, c)
	r.Unlock()
	return c, nil
}

func (r *remote) Cleanup() {
	if r.daemonPid != -1 {
		r.shutdown = true
		if r.rpcConn != nil {
			r.rpcConn.Close()
		}
		// Ask the daemon to quit
		syscall.Kill(r.daemonPid, syscall.SIGTERM)

		// Wait up to 15secs for it to stop
		for i := time.Duration(0); i < shutdownTimeout; i += time.Second {
			if !system.IsProcessAlive(r.daemonPid) {
				break
			}
			time.Sleep(time.Second)
		}

		if system.IsProcessAlive(r.daemonPid) {
			logrus.Warnf("libcontainerd: %s (%d) didn't stop within 15 secs, killing it\n", binaryName, r.daemonPid)
			syscall.Kill(r.daemonPid, syscall.SIGKILL)
		}
	}

	// cleanup some files
	os.Remove(filepath.Join(r.stateDir, pidFile))

	r.platformCleanup()
}

func (r *remote) UpdateOptions(opts ...RemoteOption) error {
	// No options can be updated yet
	// TODO: to support UpdateOptions need a lock on affected variable and to restart containerd
	return nil
}

func (r *remote) getContainerdPid() (int, error) {
	pidFile := filepath.Join(r.stateDir, pidFile)
	f, err := os.OpenFile(pidFile, os.O_RDWR, 0600)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, nil
		}
		return -1, err
	}
	defer f.Close()

	b := make([]byte, 8)
	n, err := f.Read(b)
	if err != nil && err != io.EOF {
		return -1, err
	}

	if n > 0 {
		pid, err := strconv.ParseUint(string(b[:n]), 10, 64)
		if err != nil {
			return -1, err
		}
		if system.IsProcessAlive(int(pid)) {
			logrus.Infof("libcontainerd: previous instance of containerd still alive (%d)", pid)
			return int(pid), nil
		}
	}

	return -1, nil
}

func (r *remote) getContainerdConfig() (string, error) {
	t := template.New("containerd config")
	t, err := t.Parse(configTemplate)
	if err != nil {
		return "", errors.Wrap(err, "failed to parse containerd config template")
	}

	path := filepath.Join(r.stateDir, configFile)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return "", errors.Wrapf(err, "failed to open containerd config file at %s", path)
	}
	defer f.Close()

	return path, t.Execute(f, r)
}

func (r *remote) startContainerd() error {
	pid, err := r.getContainerdPid()
	if err != nil {
		return err
	}

	if pid != -1 {
		r.daemonPid = pid
		logrus.WithField("pid", pid).
			Infof("libcontainerd: %s is still running", binaryName)
		return nil
	}

	configFile, err := r.getContainerdConfig()
	if err != nil {
		return err
	}

	args := []string{"--config", configFile}
	cmd := exec.Command(binaryName, args...)
	// redirect containerd logs to docker logs
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = containerdSysProcAttr()
	// clear the NOTIFY_SOCKET from the env when starting containerd
	cmd.Env = nil
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "NOTIFY_SOCKET") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	r.daemonWaitCh = make(chan struct{})
	go func() {
		// Reap our child when needed
		cmd.Wait()
		close(r.daemonWaitCh)
	}()

	r.daemonPid = cmd.Process.Pid

	err = ioutil.WriteFile(filepath.Join(r.stateDir, pidFile), []byte(fmt.Sprintf("%d", r.daemonPid)), 0660)
	if err != nil {
		system.KillProcess(r.daemonPid)
		return errors.Wrap(err, "libcontainerd: failed to save daemon pid to disk")
	}

	logrus.WithField("pid", r.daemonPid).
		Infof("libcontainerd: started new %s process", binaryName)

	return nil
}

func (r *remote) monitorConnection() {
	var transientFailureCount = 0

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	healthClient := grpc_health_v1.NewHealthClient(r.rpcConn)

	for {
		<-ticker.C
		ctx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
		_, err := healthClient.Check(ctx, &grpc_health_v1.HealthCheckRequest{}, grpc.FailFast(false))
		cancel()
		if err == nil {
			continue
		}

		logrus.Debugf("libcontainerd: %s health check returned error: %v", binaryName, err)

		if r.daemonPid == -1 {
			continue
		}

		if r.shutdown {
			logrus.Infof("libcontainerd: stopping %s healtcheck following graceful shutdown", binaryName)
			return
		}

		transientFailureCount++
		if transientFailureCount >= maxConnectionRetryCount || !system.IsProcessAlive(r.daemonPid) {
			transientFailureCount = 0
			if system.IsProcessAlive(r.daemonPid) {
				system.KillProcess(r.daemonPid)
			}
			<-r.daemonWaitCh
			if err := r.startContainerd(); err != nil {
				logrus.Errorf("libcontainerd: error restarting containerd: %v", err)
			}
			continue
		}
	}
}

func (r *remote) processEventStream(c *client) {
	var (
		err         error
		eventStream eventsapi.Events_StreamClient
		ev          *eventsapi.Envelope
		re          eventsapi.RuntimeEvent
	)
	defer func() {
		if err != nil {
			if r.shutdown {
				logrus.Info("libcontainerd: stop following event stream following graceful shutdown", binaryName)
				return
			}
			logrus.WithError(err).Errorf("libcontainerd: failed to process event stream")
			go r.processEventStream(c)
			return
		}
	}()

	ctx := namespaces.WithNamespace(context.Background(), c.namespace)
	eventStream, err = r.eventsSvc.Stream(ctx, &eventsapi.StreamEventsRequest{}, grpc.FailFast(false))
	if err != nil {
		return
	}

	for {
		ev, err = eventStream.Recv()
		if err != nil {
			logrus.Errorf("libcontainerd: failed to get event, leaving: %v", err)
			return
		}

		// We only care about runtime events
		switch {
		case ev.Event == nil:
			logrus.WithField("event", ev).Warnf("libcontainerd: invalid event")
			continue
		case events.Is(ev.Event, &re):
			if err := proto.Unmarshal(ev.Event.Value, &re); err != nil {
				logrus.WithField("event", ev).Errorf("libcontainerd: failed to unmarshal event")
				continue
			}
			logrus.WithFields(logrus.Fields{
				"topic":        ev.Topic,
				"RuntimeEvent": re,
			}).Debugf("libcontainerd: received event")
		default:
			logrus.WithField("topic", ev.Topic).Debugf("libcontainerd: ignoring event")
			continue
		}

		var ctr *container
		_, ctr, err = c.getContainer(context.Background(), re.ID)
		if ctr == nil {
			logrus.WithFields(logrus.Fields{
				"client":    c.namespace,
				"container": re.ID,
			}).Warnf("libcontainerd: unknown container for client")
			continue
		}

		ei := EventInfo{
			Pid:      re.Pid,
			ExitCode: re.ExitStatus,
			ExitedAt: re.ExitedAt,
		}
		ctr.ProcessEvent(toEventType(re.Type), ei)
	}
}

var containerEventToEventType = map[eventsapi.RuntimeEvent_EventType]EventType{
	eventsapi.RuntimeEvent_EXIT:       EventExit,
	eventsapi.RuntimeEvent_OOM:        EventOOM,
	eventsapi.RuntimeEvent_CREATE:     EventCreate,
	eventsapi.RuntimeEvent_START:      EventStart,
	eventsapi.RuntimeEvent_EXEC_ADDED: EventExecAdded,
	eventsapi.RuntimeEvent_PAUSED:     EventPaused,
}

func toEventType(t eventsapi.RuntimeEvent_EventType) EventType {
	et, ok := containerEventToEventType[t]
	if ok {
		return et
	}
	return EventUnknown
}
