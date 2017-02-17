package daemon

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/Sirupsen/logrus"
	apierrors "github.com/docker/docker/api/errors"
	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	networktypes "github.com/docker/docker/api/types/network"
	"github.com/docker/docker/container"
	"github.com/docker/docker/image"
	"github.com/docker/docker/layer"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/stringid"
	"github.com/docker/docker/runconfig"
	volumestore "github.com/docker/docker/volume/store"
	"github.com/opencontainers/runc/libcontainer/label"
)

// CreateManagedContainer creates a container that is managed by a Service
func (daemon *Daemon) CreateManagedContainer(params types.ContainerCreateConfig) (containertypes.ContainerCreateCreatedBody, error) {
	return daemon.containerCreate(params, true)
}

// ContainerCreate creates a regular container
func (daemon *Daemon) ContainerCreate(params types.ContainerCreateConfig) (containertypes.ContainerCreateCreatedBody, error) {
	return daemon.containerCreate(params, false)
}

func (daemon *Daemon) containerCreate(params types.ContainerCreateConfig, managed bool) (containertypes.ContainerCreateCreatedBody, error) {
	start := time.Now()

	logrus.Warn("Checking param.Config")
	if params.Config == nil {
		return containertypes.ContainerCreateCreatedBody{},
			fmt.Errorf("Config cannot be empty in order to create a container")
	}

	logrus.Warn("verifyNetworkingConfig")
	if err := daemon.verifyNetworkingConfig(params.NetworkingConfig); err != nil {
		return containertypes.ContainerCreateCreatedBody{}, err
	}

	logrus.Warn("mergeAndVerifyLogConfig")
	if err := daemon.mergeAndVerifyLogConfig(&params.HostConfig.LogConfig); err != nil {
		return containertypes.ContainerCreateCreatedBody{}, err
	}

	logrus.Warn("generateSecurityOpt")
	if opts, err := daemon.generateSecurityOpt(params.HostConfig.IpcMode, params.HostConfig.PidMode, params.HostConfig.Privileged); err != nil {
		return containertypes.ContainerCreateCreatedBody{}, err
	} else {
		params.HostConfig.SecurityOpt = append(params.HostConfig.SecurityOpt, opts...)
	}

	logrus.Warn("generateIDAndName")
	id, name, err := daemon.generateIDAndName(params.Name)
	if err != nil {
		return containertypes.ContainerCreateCreatedBody{}, err
	}
	defer func() {
		if err != nil {
			logrus.Debugf("Returning with error: %v", err)
			logrus.Debugf("Deleting id: %v", id)
			daemon.nameIndex.Delete(id)
		}
	}()

	containerOpts := []container.Option{
		container.WithManaged(managed),
		container.WithAnonymousEndpoint(params.Name == ""),
		container.WithGraphDriver(daemon.GraphDriverName()),
		container.WithName(name),
	}

	logrus.Warn("getPlatformContainerOptions")
	platOpts, err := daemon.getPlatformContainerOptions(params.HostConfig, params.Config)
	if err != nil {
		return containertypes.ContainerCreateCreatedBody{}, err
	}
	containerOpts = append(containerOpts, platOpts...)

	logrus.Warnf("Params.Config.Image: %v", params.Config.Image)
	if params.Config.Image != "" {
		var img *image.Image
		logrus.Debugf("getting image: %v", params.Config.Image)
		img, err = daemon.GetImage(params.Config.Image)
		if err != nil {
			logrus.Debug("failed to get image")
			return containertypes.ContainerCreateCreatedBody{}, err
		}

		if runtime.GOOS == "solaris" && img.OS != "solaris " {
			return containertypes.ContainerCreateCreatedBody{},
				errors.New("Platform on which parent image was created is not Solaris")
		}

		containerOpts = append(containerOpts, container.WithImage(img))
	}

	logrus.Warn("container.New")
	c, warnings, err := container.New(id, daemon.containerRoot(id), params.HostConfig, params.Config, containerOpts...)
	if err != nil {
		return containertypes.ContainerCreateCreatedBody{Warnings: warnings}, err
	}
	defer func() {
		if err != nil {
			logrus.Warnf("Calling cleanupContainer() for %v", c.ID)
			if err := daemon.cleanupContainer(c, true, true); err != nil {
				logrus.Errorf("failed to cleanup container on create error: %v", err)
			}
		}
	}()

	logrus.Warn("setRWLayer")
	if err := daemon.setRWLayer(c); err != nil {
		return containertypes.ContainerCreateCreatedBody{Warnings: warnings}, err
	}

	rootUID, rootGID, err := idtools.GetRootUIDGID(daemon.uidMaps, daemon.gidMaps)
	if err != nil {
		return containertypes.ContainerCreateCreatedBody{Warnings: warnings}, err
	}
	if err := idtools.MkdirAs(c.Root, 0700, rootUID, rootGID); err != nil {
		return containertypes.ContainerCreateCreatedBody{Warnings: warnings}, err
	}
	if err := idtools.MkdirAs(c.CheckpointDir(), 0700, rootUID, rootGID); err != nil {
		return containertypes.ContainerCreateCreatedBody{Warnings: warnings}, err
	}

	if err := daemon.setHostConfig(c, c.HostConfig); err != nil {
		return containertypes.ContainerCreateCreatedBody{Warnings: warnings}, err
	}

	if err := daemon.createContainerPlatformSpecificSettings(c, c.Config, c.HostConfig); err != nil {
		return containertypes.ContainerCreateCreatedBody{Warnings: warnings}, err
	}

	var endpointsConfigs map[string]*networktypes.EndpointSettings
	if params.NetworkingConfig != nil {
		endpointsConfigs = params.NetworkingConfig.EndpointsConfig
	}
	// Make sure NetworkMode has an acceptable value. We do this to ensure
	// backwards API compatibility.
	c.HostConfig = runconfig.SetDefaultNetModeIfBlank(c.HostConfig)

	daemon.updateContainerNetworkSettings(c, endpointsConfigs)

	logrus.Warn("ToDisk()")
	if err := c.ToDisk(); err != nil {
		logrus.Errorf("Error saving new container to disk: %v", err)
		return containertypes.ContainerCreateCreatedBody{Warnings: warnings}, err
	}
	logrus.Warn("Register():", c.ID)
	logrus.Warnf("Register(): %#v", c)
	daemon.Register(c)
	daemon.LogContainerEvent(c, "create")
	containerActions.WithValues("create").UpdateSince(start)

	return containertypes.ContainerCreateCreatedBody{ID: c.ID, Warnings: warnings}, nil
}

func (daemon *Daemon) generateSecurityOpt(ipcMode containertypes.IpcMode, pidMode containertypes.PidMode, privileged bool) ([]string, error) {
	if ipcMode.IsHost() || pidMode.IsHost() || privileged {
		return label.DisableSecOpt(), nil
	}

	var ipcLabel []string
	var pidLabel []string
	ipcContainer := ipcMode.Container()
	pidContainer := pidMode.Container()
	if ipcContainer != "" {
		c, err := daemon.GetContainer(ipcContainer)
		if err != nil {
			return nil, err
		}
		ipcLabel = label.DupSecOpt(c.ProcessLabel)
		if pidContainer == "" {
			return ipcLabel, err
		}
	}
	if pidContainer != "" {
		c, err := daemon.GetContainer(pidContainer)
		if err != nil {
			return nil, err
		}

		pidLabel = label.DupSecOpt(c.ProcessLabel)
		if ipcContainer == "" {
			return pidLabel, err
		}
	}

	if pidLabel != nil && ipcLabel != nil {
		for i := 0; i < len(pidLabel); i++ {
			if pidLabel[i] != ipcLabel[i] {
				return nil, fmt.Errorf("--ipc and --pid containers SELinux labels aren't the same")
			}
		}
		return pidLabel, nil
	}
	return nil, nil
}

func (daemon *Daemon) setRWLayer(container *container.Container) error {
	var layerID layer.ChainID
	if container.ImageID != "" {
		img, err := daemon.imageStore.Get(container.ImageID)
		if err != nil {
			return err
		}
		layerID = img.RootFS.ChainID()
	}

	rwLayerOpts := &layer.CreateRWLayerOpts{
		MountLabel: container.MountLabel,
		InitFunc:   daemon.getLayerInit(),
		StorageOpt: container.HostConfig.StorageOpt,
	}

	rwLayer, err := daemon.layerStore.CreateRWLayer(container.ID, layerID, rwLayerOpts)
	if err != nil {
		return err
	}
	container.RWLayer = rwLayer

	return nil
}

// VolumeCreate creates a volume with the specified name, driver, and opts
// This is called directly from the Engine API
func (daemon *Daemon) VolumeCreate(name, driverName string, opts, labels map[string]string) (*types.Volume, error) {
	if name == "" {
		name = stringid.GenerateNonCryptoID()
	}

	v, err := daemon.volumes.Create(name, driverName, opts, labels)
	if err != nil {
		if volumestore.IsNameConflict(err) {
			return nil, fmt.Errorf("A volume named %s already exists. Choose a different volume name.", name)
		}
		return nil, err
	}

	daemon.LogVolumeEvent(v.Name(), "create", map[string]string{"driver": v.DriverName()})
	apiV := volumeToAPIType(v)
	apiV.Mountpoint = v.Path()
	return apiV, nil
}

func (daemon *Daemon) mergeAndVerifyConfig(config *containertypes.Config, img *image.Image) error {
	if img != nil && img.Config != nil {
		if err := merge(config, img.Config); err != nil {
			return err
		}
	}
	// Reset the Entrypoint if it is [""]
	if len(config.Entrypoint) == 1 && config.Entrypoint[0] == "" {
		config.Entrypoint = nil
	}
	if len(config.Entrypoint) == 0 && len(config.Cmd) == 0 {
		return fmt.Errorf("No command specified")
	}
	return nil
}

// Checks if the client set configurations for more than one network while creating a container
// Also checks if the IPAMConfig is valid
func (daemon *Daemon) verifyNetworkingConfig(nwConfig *networktypes.NetworkingConfig) error {
	if nwConfig == nil || len(nwConfig.EndpointsConfig) == 0 {
		return nil
	}
	if len(nwConfig.EndpointsConfig) == 1 {
		for _, v := range nwConfig.EndpointsConfig {
			if v != nil && v.IPAMConfig != nil {
				if v.IPAMConfig.IPv4Address != "" && net.ParseIP(v.IPAMConfig.IPv4Address).To4() == nil {
					return apierrors.NewBadRequestError(fmt.Errorf("invalid IPv4 address: %s", v.IPAMConfig.IPv4Address))
				}
				if v.IPAMConfig.IPv6Address != "" {
					n := net.ParseIP(v.IPAMConfig.IPv6Address)
					// if the address is an invalid network address (ParseIP == nil) or if it is
					// an IPv4 address (To4() != nil), then it is an invalid IPv6 address
					if n == nil || n.To4() != nil {
						return apierrors.NewBadRequestError(fmt.Errorf("invalid IPv6 address: %s", v.IPAMConfig.IPv6Address))
					}
				}
			}
		}
		return nil
	}
	l := make([]string, 0, len(nwConfig.EndpointsConfig))
	for k := range nwConfig.EndpointsConfig {
		l = append(l, k)
	}
	err := fmt.Errorf("Container cannot be connected to network endpoints: %s", strings.Join(l, ", "))
	return apierrors.NewBadRequestError(err)
}
