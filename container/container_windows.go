// +build windows

package container

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Sirupsen/logrus"
	containertypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/sysinfo"
	"github.com/pkg/errors"
)

const (
	windowsMinCPUShares  = 1
	windowsMaxCPUShares  = 10000
	windowsMinCPUPercent = 1
	windowsMaxCPUPercent = 100
	windowsMinCPUCount   = 1
)

// Container holds fields specific to the Windows implementation. See
// CommonContainer for standard fields common to all containers.
type Container struct {
	CommonContainer

	// Fields below here are platform specific.
}

// ExitStatus provides exit reasons for a container.
type ExitStatus struct {
	// The exit code with which the container exited.
	ExitCode int
}

// CreateDaemonEnvironment creates a new environment variable slice for this container.
func (container *Container) CreateDaemonEnvironment(_ bool, linkedEnv []string) []string {
	// because the env on the container can override certain default values
	// we need to replace the 'env' keys where they match and append anything
	// else.
	return ReplaceOrAppendEnvValues(linkedEnv, container.Config.Env)
}

// UnmountIpcMounts unmounts Ipc related mounts.
// This is a NOOP on windows.
func (container *Container) UnmountIpcMounts(unmount func(pth string) error) {
}

// IpcMounts returns the list of Ipc related mounts.
func (container *Container) IpcMounts() []Mount {
	return nil
}

// SecretMount returns the mount for the secret path
func (container *Container) SecretMount() *Mount {
	return nil
}

// UnmountSecrets unmounts the fs for secrets
func (container *Container) UnmountSecrets() error {
	return nil
}

// DetachAndUnmount unmounts all volumes.
// On Windows it only delegates to `UnmountVolumes` since there is nothing to
// force unmount.
func (container *Container) DetachAndUnmount(volumeEventLog func(name, action string, attributes map[string]string)) error {
	return container.UnmountVolumes(volumeEventLog)
}

// TmpfsMounts returns the list of tmpfs mounts
func (container *Container) TmpfsMounts() ([]Mount, error) {
	var mounts []Mount
	return mounts, nil
}

// UpdateContainer updates configuration of a container
func (container *Container) UpdateContainer(hostConfig *containertypes.HostConfig) error {
	container.Lock()
	defer container.Unlock()
	resources := hostConfig.Resources
	if resources.BlkioWeight != 0 || resources.CPUShares != 0 ||
		resources.CPUPeriod != 0 || resources.CPUQuota != 0 ||
		resources.CpusetCpus != "" || resources.CpusetMems != "" ||
		resources.Memory != 0 || resources.MemorySwap != 0 ||
		resources.MemoryReservation != 0 || resources.KernelMemory != 0 {
		return fmt.Errorf("Resource updating isn't supported on Windows")
	}
	// update HostConfig of container
	if hostConfig.RestartPolicy.Name != "" {
		if container.HostConfig.AutoRemove && !hostConfig.RestartPolicy.IsNone() {
			return fmt.Errorf("Restart policy cannot be updated because AutoRemove is enabled for the container")
		}
		container.HostConfig.RestartPolicy = hostConfig.RestartPolicy
	}
	return nil
}

// cleanResourcePath cleans a resource path by removing C:\ syntax, and prepares
// to combine with a volume path
func cleanResourcePath(path string) string {
	if len(path) >= 2 {
		c := path[0]
		if path[1] == ':' && ('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
			path = path[2:]
		}
	}
	return filepath.Join(string(os.PathSeparator), path)
}

// BuildHostnameFile writes the container's hostname file.
func (container *Container) BuildHostnameFile() error {
	return nil
}

// EnableServiceDiscoveryOnDefaultNetwork Enable service discovery on default network
func (container *Container) EnableServiceDiscoveryOnDefaultNetwork() bool {
	return true
}
func WithAdjustCPUShares() Option {
	return func(c *Container) (warnings []string, err error) {
		return
	}
}
func WithHyperv(isHyperv bool) Option {
	return func(c *Container) (warnings []string, err error) {
		if c.HostConfig == nil {
			return nil, errors.Errorf("WithHyperV() needs to be provided after WithHostConfig()")
		}

		if !isHyperv {
			var msg string

			resources := &c.HostConfig.Resources

			// The processor resource controls are mutually exclusive on
			// Windows Server Containers, the order of precedence is
			// CPUCount first, then CPUShares, and CPUPercent last.
			if resources.CPUCount > 0 {
				if resources.CPUShares > 0 {
					msg = "Conflicting options: CPU count takes priority over CPU shares on Windows Server Containers. CPU shares discarded"
					warnings = append(warnings, msg)
					logrus.Warn(msg)
					resources.CPUShares = 0
				}
				if resources.CPUPercent > 0 {
					msg = "Conflicting options: CPU count takes priority over CPU percent on Windows Server Containers. CPU percent discarded"
					warnings = append(warnings, msg)
					logrus.Warn(msg)
					resources.CPUPercent = 0
				}
			} else if resources.CPUShares > 0 {
				if resources.CPUPercent > 0 {
					msg = "Conflicting options: CPU shares takes priority over CPU percent on Windows Server Containers. CPU percent discarded"
					warnings = append(warnings, msg)
					logrus.Warn(msg)
					resources.CPUPercent = 0
				}
			}
		}

		return
	}
}

func validatePlatformHostConfig(config *containertypes.HostConfig) (warnings []string, err error) {
	return verifyContainerResources(&config.Resources)
}

func validatePlatformContainerConfig(config *containertypes.Config) (warnings []string, err error) {
	return
}

func verifyContainerResources(resources *containertypes.Resources) ([]string, error) {
	if resources.CPUShares < 0 || resources.CPUShares > windowsMaxCPUShares {
		return nil, fmt.Errorf("range of CPUShares is from %d to %d", windowsMinCPUShares, windowsMaxCPUShares)
	}
	if resources.CPUPercent < 0 || resources.CPUPercent > windowsMaxCPUPercent {
		return nil, fmt.Errorf("range of CPUPercent is from %d to %d", windowsMinCPUPercent, windowsMaxCPUPercent)
	}
	if resources.CPUCount < 0 {
		return nil, fmt.Errorf("invalid CPUCount: CPUCount cannot be negative")
	}

	if resources.NanoCPUs > 0 && resources.CPUPercent > 0 {
		return nil, fmt.Errorf("conflicting options: Nano CPUs and CPU Percent cannot both be set")
	}
	if resources.NanoCPUs > 0 && resources.CPUShares > 0 {
		return nil, fmt.Errorf("conflicting options: Nano CPUs and CPU Shares cannot both be set")
	}
	// The precision we could get is 0.01, because on Windows we have to convert to CPUPercent.
	// We don't set the lower limit here and it is up to the underlying platform (e.g., Windows) to return an error.
	if resources.NanoCPUs < 0 || resources.NanoCPUs > int64(sysinfo.NumCPU())*1e9 {
		return nil, fmt.Errorf("range of CPUs is from 0.01 to %d.00, as there are only %d CPUs available", sysinfo.NumCPU(), sysinfo.NumCPU())
	}

	if len(resources.BlkioDeviceReadBps) > 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support BlkioDeviceReadBps")
	}
	if len(resources.BlkioDeviceReadIOps) > 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support BlkioDeviceReadIOps")
	}
	if len(resources.BlkioDeviceWriteBps) > 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support BlkioDeviceWriteBps")
	}
	if len(resources.BlkioDeviceWriteIOps) > 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support BlkioDeviceWriteIOps")
	}
	if resources.BlkioWeight > 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support BlkioWeight")
	}
	if len(resources.BlkioWeightDevice) > 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support BlkioWeightDevice")
	}
	if resources.CgroupParent != "" {
		return nil, fmt.Errorf("invalid option: Windows does not support CgroupParent")
	}
	if resources.CPUPeriod != 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support CPUPeriod")
	}
	if resources.CpusetCpus != "" {
		return nil, fmt.Errorf("invalid option: Windows does not support CpusetCpus")
	}
	if resources.CpusetMems != "" {
		return nil, fmt.Errorf("invalid option: Windows does not support CpusetMems")
	}
	if resources.KernelMemory != 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support KernelMemory")
	}
	if resources.MemoryReservation != 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support MemoryReservation")
	}
	if resources.MemorySwap != 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support MemorySwap")
	}
	if resources.MemorySwappiness != nil && *resources.MemorySwappiness != -1 {
		return nil, fmt.Errorf("invalid option: Windows does not support MemorySwappiness")
	}
	if resources.OomKillDisable != nil && *resources.OomKillDisable {
		return nil, fmt.Errorf("invalid option: Windows does not support OomKillDisable")
	}
	if resources.PidsLimit != 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support PidsLimit")
	}
	if len(resources.Ulimits) != 0 {
		return nil, fmt.Errorf("invalid option: Windows does not support Ulimits")
	}
	return nil, nil
}

func (container *Container) setSecurityOption(opts []string) error {
	return nil
}
