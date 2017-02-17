// +build solaris,cgo

package daemon

import (
	"fmt"
	"net"
	"strconv"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/api/types"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/container"
	"github.com/docker/docker/image"
	"github.com/docker/docker/layer"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/parsers/kernel"
	refstore "github.com/docker/docker/reference"
	"github.com/docker/libnetwork"
	nwconfig "github.com/docker/libnetwork/config"
	"github.com/docker/libnetwork/drivers/solaris/bridge"
	"github.com/docker/libnetwork/netlabel"
	"github.com/docker/libnetwork/netutils"
	lntypes "github.com/docker/libnetwork/types"
	"github.com/opencontainers/runc/libcontainer/label"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
)

//#include <zone.h>
import "C"

const (
	defaultVirtualSwitch = "Virtual Switch"
	platformSupported    = true
	solarisMinCPUShares  = 1
	solarisMaxCPUShares  = 65535
)

func getMemoryResources(config containertypes.Resources) specs.CappedMemory {
	memory := specs.CappedMemory{}

	if config.Memory > 0 {
		memory.Physical = strconv.FormatInt(config.Memory, 10)
	}

	if config.MemorySwap != 0 {
		memory.Swap = strconv.FormatInt(config.MemorySwap, 10)
	}

	return memory
}

func getCPUResources(config containertypes.Resources) specs.CappedCPU {
	cpu := specs.CappedCPU{}

	if config.CpusetCpus != "" {
		cpu.Ncpus = config.CpusetCpus
	}

	return cpu
}

func (daemon *Daemon) cleanupMountsByID(id string) error {
	return nil
}

func parseSecurityOpt(container *container.Container, config *containertypes.HostConfig) error {
	//Since config.SecurityOpt is specifically defined as a "List of string values to
	//customize labels for MLs systems, such as SELinux"
	//until we figure out how to map to Trusted Extensions
	//this is being disabled for now on Solaris
	var (
		labelOpts []string
		err       error
	)

	if len(config.SecurityOpt) > 0 {
		return errors.New("Security options are not supported on Solaris")
	}

	container.ProcessLabel, container.MountLabel, err = label.InitLabels(labelOpts)
	return err
}

func setupRemappedRoot(config *Config) ([]idtools.IDMap, []idtools.IDMap, error) {
	return nil, nil, nil
}

func setupDaemonRoot(config *Config, rootDir string, rootUID, rootGID int) error {
	return nil
}

func (daemon *Daemon) getLayerInit() func(string) error {
	return nil
}

func checkKernel() error {
	// solaris can rely upon checkSystem() below, we don't skew kernel versions
	return nil
}

func (daemon *Daemon) getCgroupDriver() string {
	return ""
}

// UsingSystemd returns true if cli option includes native.cgroupdriver=systemd
func UsingSystemd(config *Config) bool {
	return false
}

// platformReload updates configuration with platform specific options
func (daemon *Daemon) platformReload(config *Config) map[string]string {
	return map[string]string{}
}

// verifyDaemonSettings performs validation of daemon config struct
func verifyDaemonSettings(config *Config) error {

	if config.DefaultRuntime == "" {
		config.DefaultRuntime = stockRuntimeName
	}
	if config.Runtimes == nil {
		config.Runtimes = make(map[string]types.Runtime)
	}
	stockRuntimeOpts := []string{}
	config.Runtimes[stockRuntimeName] = types.Runtime{Path: DefaultRuntimeBinary, Args: stockRuntimeOpts}

	// checkSystem validates platform-specific requirements
	return nil
}

func checkSystem() error {
	// check OS version for compatibility, ensure running in global zone
	var err error
	var id C.zoneid_t

	if id, err = C.getzoneid(); err != nil {
		return fmt.Errorf("Exiting. Error getting zone id: %+v", err)
	}
	if int(id) != 0 {
		return fmt.Errorf("Exiting because the Docker daemon is not running in the global zone")
	}

	v, err := kernel.GetKernelVersion()
	if kernel.CompareKernelVersion(*v, kernel.VersionInfo{Kernel: 5, Major: 12, Minor: 0}) < 0 {
		return fmt.Errorf("Your Solaris kernel version: %s doesn't support Docker. Please upgrade to 5.12.0", v.String())
	}
	return err
}

// configureMaxThreads sets the Go runtime max threads threshold
// which is 90% of the kernel setting from /proc/sys/kernel/threads-max
func configureMaxThreads(config *Config) error {
	return nil
}

// configureKernelSecuritySupport configures and validate security support for the kernel
func configureKernelSecuritySupport(config *Config, driverName string) error {
	return nil
}

func (daemon *Daemon) initNetworkController(config *Config, activeSandboxes map[string]interface{}) (libnetwork.NetworkController, error) {
	netOptions, err := daemon.networkOptions(config, daemon.PluginStore, activeSandboxes)
	if err != nil {
		return nil, err
	}

	controller, err := libnetwork.New(netOptions...)
	if err != nil {
		return nil, fmt.Errorf("error obtaining controller instance: %v", err)
	}

	// Initialize default network on "null"
	if _, err := controller.NewNetwork("null", "none", "", libnetwork.NetworkOptionPersist(false)); err != nil {
		return nil, fmt.Errorf("Error creating default 'null' network: %v", err)
	}

	if !config.DisableBridge {
		// Initialize default driver "bridge"
		if err := initBridgeDriver(controller, config); err != nil {
			return nil, err
		}
	}

	return controller, nil
}

func initBridgeDriver(controller libnetwork.NetworkController, config *Config) error {
	if n, err := controller.NetworkByName("bridge"); err == nil {
		if err = n.Delete(); err != nil {
			return fmt.Errorf("could not delete the default bridge network: %v", err)
		}
	}

	bridgeName := bridge.DefaultBridgeName
	if config.bridgeConfig.Iface != "" {
		bridgeName = config.bridgeConfig.Iface
	}
	netOption := map[string]string{
		bridge.BridgeName:    bridgeName,
		bridge.DefaultBridge: strconv.FormatBool(true),
		netlabel.DriverMTU:   strconv.Itoa(config.Mtu),
		bridge.EnableICC:     strconv.FormatBool(config.bridgeConfig.InterContainerCommunication),
	}

	// --ip processing
	if config.bridgeConfig.DefaultIP != nil {
		netOption[bridge.DefaultBindingIP] = config.bridgeConfig.DefaultIP.String()
	}

	var ipamV4Conf *libnetwork.IpamConf

	ipamV4Conf = &libnetwork.IpamConf{AuxAddresses: make(map[string]string)}

	nwList, _, err := netutils.ElectInterfaceAddresses(bridgeName)
	if err != nil {
		return errors.Wrap(err, "list bridge addresses failed")
	}

	nw := nwList[0]
	if len(nwList) > 1 && config.bridgeConfig.FixedCIDR != "" {
		_, fCIDR, err := net.ParseCIDR(config.bridgeConfig.FixedCIDR)
		if err != nil {
			return errors.Wrap(err, "parse CIDR failed")
		}
		// Iterate through in case there are multiple addresses for the bridge
		for _, entry := range nwList {
			if fCIDR.Contains(entry.IP) {
				nw = entry
				break
			}
		}
	}

	ipamV4Conf.PreferredPool = lntypes.GetIPNetCanonical(nw).String()
	hip, _ := lntypes.GetHostPartIP(nw.IP, nw.Mask)
	if hip.IsGlobalUnicast() {
		ipamV4Conf.Gateway = nw.IP.String()
	}

	if config.bridgeConfig.IP != "" {
		ipamV4Conf.PreferredPool = config.bridgeConfig.IP
		ip, _, err := net.ParseCIDR(config.bridgeConfig.IP)
		if err != nil {
			return err
		}
		ipamV4Conf.Gateway = ip.String()
	} else if bridgeName == bridge.DefaultBridgeName && ipamV4Conf.PreferredPool != "" {
		logrus.Infof("Default bridge (%s) is assigned with an IP address %s. Daemon option --bip can be used to set a preferred IP address", bridgeName, ipamV4Conf.PreferredPool)
	}

	if config.bridgeConfig.FixedCIDR != "" {
		_, fCIDR, err := net.ParseCIDR(config.bridgeConfig.FixedCIDR)
		if err != nil {
			return err
		}

		ipamV4Conf.SubPool = fCIDR.String()
	}

	if config.bridgeConfig.DefaultGatewayIPv4 != nil {
		ipamV4Conf.AuxAddresses["DefaultGatewayIPv4"] = config.bridgeConfig.DefaultGatewayIPv4.String()
	}

	v4Conf := []*libnetwork.IpamConf{ipamV4Conf}
	v6Conf := []*libnetwork.IpamConf{}

	// Initialize default network on "bridge" with the same name
	_, err = controller.NewNetwork("bridge", "bridge", "",
		libnetwork.NetworkOptionDriverOpts(netOption),
		libnetwork.NetworkOptionIpam("default", "", v4Conf, v6Conf, nil),
		libnetwork.NetworkOptionDeferIPv6Alloc(false))
	if err != nil {
		return fmt.Errorf("Error creating default 'bridge' network: %v", err)
	}
	return nil
}

// registerLinks sets up links between containers and writes the
// configuration out for persistence.
func (daemon *Daemon) registerLinks(container *container.Container, hostConfig *containertypes.HostConfig) error {
	return nil
}

func (daemon *Daemon) cleanupMounts() error {
	return nil
}

// conditionalMountOnStart is a platform specific helper function during the
// container start to call mount.
func (daemon *Daemon) conditionalMountOnStart(container *container.Container) error {
	return daemon.Mount(container)
}

// conditionalUnmountOnCleanup is a platform specific helper function called
// during the cleanup of a container to unmount.
func (daemon *Daemon) conditionalUnmountOnCleanup(container *container.Container) error {
	return daemon.Unmount(container)
}

func restoreCustomImage(is image.Store, ls layer.Store, rs refstore.Store) error {
	// Solaris has no custom images to register
	return nil
}

func driverOptions(config *Config) []nwconfig.Option {
	return []nwconfig.Option{}
}

func (daemon *Daemon) stats(c *container.Container) (*types.StatsJSON, error) {
	return nil, nil
}

// setDefaultIsolation determine the default isolation mode for the
// daemon to run in. This is only applicable on Windows
func (daemon *Daemon) setDefaultIsolation() error {
	return nil
}

func rootFSToAPIType(rootfs *image.RootFS) types.RootFS {
	return types.RootFS{}
}

func setupDaemonProcess(config *Config) error {
	return nil
}

func (daemon *Daemon) setupSeccompProfile() error {
	return nil
}

func (daemon *Daemon) getPlatformContainerOptions(hostConfig *containertypes.HostConfig, config *containertypes.Config) (options []container.Option, err error) {
	return
}
