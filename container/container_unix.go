// +build linux freebsd solaris

package container

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Sirupsen/logrus"
	pblkiodev "github.com/docker/docker/api/types/blkiodev"
	containertypes "github.com/docker/docker/api/types/container"
	mounttypes "github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/pkg/chrootarchive"
	"github.com/docker/docker/pkg/parsers/kernel"
	"github.com/docker/docker/pkg/stringid"
	"github.com/docker/docker/pkg/symlink"
	"github.com/docker/docker/pkg/sysinfo"
	"github.com/docker/docker/pkg/system"
	"github.com/docker/docker/volume"
	"github.com/opencontainers/runc/libcontainer/label"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	containerSecretMountPath = "/run/secrets"

	// See https://git.kernel.org/cgit/linux/kernel/git/tip/tip.git/tree/kernel/sched/sched.h?id=8cd9234c64c584432f6992fe944ca9e46ca8ea76#n269
	linuxMinCPUShares = 2
	linuxMaxCPUShares = 262144

	// It's not kernel limit, we want this 4M limit to supply a reasonable functional container
	linuxMinMemory = 4194304
)

// Container holds the fields specific to unixen implementations.
// See CommonContainer for standard fields common to all containers.
type Container struct {
	CommonContainer

	// Fields below here are platform specific.
	AppArmorProfile string
	HostnamePath    string
	HostsPath       string
	ShmPath         string
	ResolvConfPath  string
	SeccompProfile  string
	NoNewPrivileges bool
}

// ExitStatus provides exit reasons for a container.
type ExitStatus struct {
	// The exit code with which the container exited.
	ExitCode int

	// Whether the container encountered an OOM.
	OOMKilled bool
}

// CreateDaemonEnvironment returns the list of all environment variables given the list of
// environment variables related to links.
// Sets PATH, HOSTNAME and if container.Config.Tty is set: TERM.
// The defaults set here do not override the values in container.Config.Env
func (container *Container) CreateDaemonEnvironment(tty bool, linkedEnv []string) []string {
	// Setup environment
	env := []string{
		"PATH=" + system.DefaultPathEnv,
		"HOSTNAME=" + container.Config.Hostname,
	}
	if tty {
		env = append(env, "TERM=xterm")
	}
	env = append(env, linkedEnv...)
	// because the env on the container can override certain default values
	// we need to replace the 'env' keys where they match and append anything
	// else.
	env = ReplaceOrAppendEnvValues(env, container.Config.Env)
	return env
}

// TrySetNetworkMount attempts to set the network mounts given a provided destination and
// the path to use for it; return true if the given destination was a network mount file
func (container *Container) TrySetNetworkMount(destination string, path string) bool {
	if destination == "/etc/resolv.conf" {
		container.ResolvConfPath = path
		return true
	}
	if destination == "/etc/hostname" {
		container.HostnamePath = path
		return true
	}
	if destination == "/etc/hosts" {
		container.HostsPath = path
		return true
	}

	return false
}

// BuildHostnameFile writes the container's hostname file.
func (container *Container) BuildHostnameFile() error {
	hostnamePath, err := container.GetRootResourcePath("hostname")
	if err != nil {
		return err
	}
	container.HostnamePath = hostnamePath
	return ioutil.WriteFile(container.HostnamePath, []byte(container.Config.Hostname+"\n"), 0644)
}

// NetworkMounts returns the list of network mounts.
func (container *Container) NetworkMounts() []Mount {
	var mounts []Mount
	shared := container.HostConfig.NetworkMode.IsContainer()
	if container.ResolvConfPath != "" {
		if _, err := os.Stat(container.ResolvConfPath); err != nil {
			logrus.Warnf("ResolvConfPath set to %q, but can't stat this filename (err = %v); skipping", container.ResolvConfPath, err)
		} else {
			if !container.HasMountFor("/etc/resolv.conf") {
				label.Relabel(container.ResolvConfPath, container.MountLabel, shared)
			}
			writable := !container.HostConfig.ReadonlyRootfs
			if m, exists := container.MountPoints["/etc/resolv.conf"]; exists {
				writable = m.RW
			}
			mounts = append(mounts, Mount{
				Source:      container.ResolvConfPath,
				Destination: "/etc/resolv.conf",
				Writable:    writable,
				Propagation: string(volume.DefaultPropagationMode),
			})
		}
	}
	if container.HostnamePath != "" {
		if _, err := os.Stat(container.HostnamePath); err != nil {
			logrus.Warnf("HostnamePath set to %q, but can't stat this filename (err = %v); skipping", container.HostnamePath, err)
		} else {
			if !container.HasMountFor("/etc/hostname") {
				label.Relabel(container.HostnamePath, container.MountLabel, shared)
			}
			writable := !container.HostConfig.ReadonlyRootfs
			if m, exists := container.MountPoints["/etc/hostname"]; exists {
				writable = m.RW
			}
			mounts = append(mounts, Mount{
				Source:      container.HostnamePath,
				Destination: "/etc/hostname",
				Writable:    writable,
				Propagation: string(volume.DefaultPropagationMode),
			})
		}
	}
	if container.HostsPath != "" {
		if _, err := os.Stat(container.HostsPath); err != nil {
			logrus.Warnf("HostsPath set to %q, but can't stat this filename (err = %v); skipping", container.HostsPath, err)
		} else {
			if !container.HasMountFor("/etc/hosts") {
				label.Relabel(container.HostsPath, container.MountLabel, shared)
			}
			writable := !container.HostConfig.ReadonlyRootfs
			if m, exists := container.MountPoints["/etc/hosts"]; exists {
				writable = m.RW
			}
			mounts = append(mounts, Mount{
				Source:      container.HostsPath,
				Destination: "/etc/hosts",
				Writable:    writable,
				Propagation: string(volume.DefaultPropagationMode),
			})
		}
	}
	return mounts
}

// SecretMountPath returns the path of the secret mount for the container
func (container *Container) SecretMountPath() string {
	return filepath.Join(container.Root, "secrets")
}

// CopyImagePathContent copies files in destination to the volume.
func (container *Container) CopyImagePathContent(v volume.Volume, destination string) error {
	rootfs, err := symlink.FollowSymlinkInScope(filepath.Join(container.BaseFS, destination), container.BaseFS)
	if err != nil {
		return err
	}

	if _, err = ioutil.ReadDir(rootfs); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	id := stringid.GenerateNonCryptoID()
	path, err := v.Mount(id)
	if err != nil {
		return err
	}

	defer func() {
		if err := v.Unmount(id); err != nil {
			logrus.Warnf("error while unmounting volume %s: %v", v.Name(), err)
		}
	}()
	if err := label.Relabel(path, container.MountLabel, true); err != nil && err != unix.ENOTSUP {
		return err
	}
	return copyExistingContents(rootfs, path)
}

// ShmResourcePath returns path to shm
func (container *Container) ShmResourcePath() (string, error) {
	return container.GetRootResourcePath("shm")
}

// HasMountFor checks if path is a mountpoint
func (container *Container) HasMountFor(path string) bool {
	_, exists := container.MountPoints[path]
	return exists
}

// UnmountIpcMounts uses the provided unmount function to unmount shm and mqueue if they were mounted
func (container *Container) UnmountIpcMounts(unmount func(pth string) error) {
	if container.HostConfig.IpcMode.IsContainer() || container.HostConfig.IpcMode.IsHost() {
		return
	}

	var warnings []string

	if !container.HasMountFor("/dev/shm") {
		shmPath, err := container.ShmResourcePath()
		if err != nil {
			logrus.Error(err)
			warnings = append(warnings, err.Error())
		} else if shmPath != "" {
			if err := unmount(shmPath); err != nil && !os.IsNotExist(err) {
				warnings = append(warnings, fmt.Sprintf("failed to umount %s: %v", shmPath, err))
			}

		}
	}

	if len(warnings) > 0 {
		logrus.Warnf("failed to cleanup ipc mounts:\n%v", strings.Join(warnings, "\n"))
	}
}

// IpcMounts returns the list of IPC mounts
func (container *Container) IpcMounts() []Mount {
	var mounts []Mount

	if !container.HasMountFor("/dev/shm") {
		label.SetFileLabel(container.ShmPath, container.MountLabel)
		mounts = append(mounts, Mount{
			Source:      container.ShmPath,
			Destination: "/dev/shm",
			Writable:    true,
			Propagation: string(volume.DefaultPropagationMode),
		})
	}

	return mounts
}

// SecretMount returns the mount for the secret path
func (container *Container) SecretMount() *Mount {
	if len(container.SecretReferences) > 0 {
		return &Mount{
			Source:      container.SecretMountPath(),
			Destination: containerSecretMountPath,
			Writable:    false,
		}
	}

	return nil
}

// UnmountSecrets unmounts the local tmpfs for secrets
func (container *Container) UnmountSecrets() error {
	if _, err := os.Stat(container.SecretMountPath()); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return detachMounted(container.SecretMountPath())
}

// UpdateContainer updates configuration of a container.
func (container *Container) UpdateContainer(hostConfig *containertypes.HostConfig) error {
	container.Lock()
	defer container.Unlock()

	// update resources of container
	resources := hostConfig.Resources
	cResources := &container.HostConfig.Resources
	if resources.BlkioWeight != 0 {
		cResources.BlkioWeight = resources.BlkioWeight
	}
	if resources.CPUShares != 0 {
		cResources.CPUShares = resources.CPUShares
	}
	if resources.CPUPeriod != 0 {
		cResources.CPUPeriod = resources.CPUPeriod
	}
	if resources.CPUQuota != 0 {
		cResources.CPUQuota = resources.CPUQuota
	}
	if resources.CpusetCpus != "" {
		cResources.CpusetCpus = resources.CpusetCpus
	}
	if resources.CpusetMems != "" {
		cResources.CpusetMems = resources.CpusetMems
	}
	if resources.Memory != 0 {
		// if memory limit smaller than already set memoryswap limit and doesn't
		// update the memoryswap limit, then error out.
		if resources.Memory > cResources.MemorySwap && resources.MemorySwap == 0 {
			return fmt.Errorf("Memory limit should be smaller than already set memoryswap limit, update the memoryswap at the same time")
		}
		cResources.Memory = resources.Memory
	}
	if resources.MemorySwap != 0 {
		cResources.MemorySwap = resources.MemorySwap
	}
	if resources.MemoryReservation != 0 {
		cResources.MemoryReservation = resources.MemoryReservation
	}
	if resources.KernelMemory != 0 {
		cResources.KernelMemory = resources.KernelMemory
	}

	// update HostConfig of container
	if hostConfig.RestartPolicy.Name != "" {
		if container.HostConfig.AutoRemove && !hostConfig.RestartPolicy.IsNone() {
			return fmt.Errorf("Restart policy cannot be updated because AutoRemove is enabled for the container")
		}
		container.HostConfig.RestartPolicy = hostConfig.RestartPolicy
	}

	if err := container.ToDisk(); err != nil {
		logrus.Errorf("Error saving updated container: %v", err)
		return err
	}

	return nil
}

// DetachAndUnmount uses a detached mount on all mount destinations, then
// unmounts each volume normally.
// This is used from daemon/archive for `docker cp`
func (container *Container) DetachAndUnmount(volumeEventLog func(name, action string, attributes map[string]string)) error {
	networkMounts := container.NetworkMounts()
	mountPaths := make([]string, 0, len(container.MountPoints)+len(networkMounts))

	for _, mntPoint := range container.MountPoints {
		dest, err := container.GetResourcePath(mntPoint.Destination)
		if err != nil {
			logrus.Warnf("Failed to get volume destination path for container '%s' at '%s' while lazily unmounting: %v", container.ID, mntPoint.Destination, err)
			continue
		}
		mountPaths = append(mountPaths, dest)
	}

	for _, m := range networkMounts {
		dest, err := container.GetResourcePath(m.Destination)
		if err != nil {
			logrus.Warnf("Failed to get volume destination path for container '%s' at '%s' while lazily unmounting: %v", container.ID, m.Destination, err)
			continue
		}
		mountPaths = append(mountPaths, dest)
	}

	for _, mountPath := range mountPaths {
		if err := detachMounted(mountPath); err != nil {
			logrus.Warnf("%s unmountVolumes: Failed to do lazy umount fo volume '%s': %v", container.ID, mountPath, err)
		}
	}
	return container.UnmountVolumes(volumeEventLog)
}

// copyExistingContents copies from the source to the destination and
// ensures the ownership is appropriately set.
func copyExistingContents(source, destination string) error {
	volList, err := ioutil.ReadDir(source)
	if err != nil {
		return err
	}
	if len(volList) > 0 {
		srcList, err := ioutil.ReadDir(destination)
		if err != nil {
			return err
		}
		if len(srcList) == 0 {
			// If the source volume is empty, copies files from the root into the volume
			if err := chrootarchive.CopyWithTar(source, destination); err != nil {
				return err
			}
		}
	}
	return copyOwnership(source, destination)
}

// copyOwnership copies the permissions and uid:gid of the source file
// to the destination file
func copyOwnership(source, destination string) error {
	stat, err := system.Stat(source)
	if err != nil {
		return err
	}

	if err := os.Chown(destination, int(stat.UID()), int(stat.GID())); err != nil {
		return err
	}

	return os.Chmod(destination, os.FileMode(stat.Mode()))
}

// TmpfsMounts returns the list of tmpfs mounts
func (container *Container) TmpfsMounts() ([]Mount, error) {
	var mounts []Mount
	for dest, data := range container.HostConfig.Tmpfs {
		mounts = append(mounts, Mount{
			Source:      "tmpfs",
			Destination: dest,
			Data:        data,
		})
	}
	for dest, mnt := range container.MountPoints {
		if mnt.Type == mounttypes.TypeTmpfs {
			data, err := volume.ConvertTmpfsOptions(mnt.Spec.TmpfsOptions, mnt.Spec.ReadOnly)
			if err != nil {
				return nil, err
			}
			mounts = append(mounts, Mount{
				Source:      "tmpfs",
				Destination: dest,
				Data:        data,
			})
		}
	}
	return mounts, nil
}

// cleanResourcePath cleans a resource path and prepares to combine with mnt path
func cleanResourcePath(path string) string {
	return filepath.Join(string(os.PathSeparator), path)
}

// EnableServiceDiscoveryOnDefaultNetwork Enable service discovery on default network
func (container *Container) EnableServiceDiscoveryOnDefaultNetwork() bool {
	return false
}

func WithDefaultShmSize(size int64) Option {
	return func(c *Container) ([]string, error) {
		if c.HostConfig.ShmSize == 0 {
			c.HostConfig.ShmSize = size
		}
		return nil, nil
	}
}

func WithUserNS() Option {
	return func(c *Container) ([]string, error) {
		if c.HostConfig == nil {
			return nil, errors.Errorf("WithUserNS() needs to be provided after WithHostConfig()")
		}

		// check for various conflicting options with user namespaces
		if c.HostConfig.UsernsMode.IsPrivate() {
			if c.HostConfig.Privileged {
				return nil, errors.Errorf("Privileged mode is incompatible with user namespaces")
			}
			if c.HostConfig.NetworkMode.IsHost() && !c.HostConfig.UsernsMode.IsHost() {
				return nil, errors.Errorf("Cannot share the host's network namespace when user namespaces are enabled")
			}
			if c.HostConfig.PidMode.IsHost() && !c.HostConfig.UsernsMode.IsHost() {
				return nil, errors.Errorf("Cannot share the host PID namespace when user namespaces are enabled")
			}
		}

		return nil, nil
	}
}

func WithSystemd() Option {
	return func(c *Container) ([]string, error) {
		if c.HostConfig == nil {
			return nil, errors.Errorf("WithSystemd() needs to be provided after WithHostConfig()")
		}

		// CgroupParent for systemd cgroup should be named as "xxx.slice"
		if len(c.HostConfig.CgroupParent) <= 6 || !strings.HasSuffix(c.HostConfig.CgroupParent, ".slice") {
			return nil, errors.Errorf(`cgroup-parent for systemd cgroup should be a valid slice named as "xxx.slice"`)
		}

		return nil, nil
	}
}

func WithAdjustCPUShares() Option {
	return func(c *Container) (warnings []string, err error) {
		hostConfig := c.HostConfig
		if hostConfig.CPUShares <= 0 {
			return
		}

		// Handle unsupported CPUShares
		if hostConfig.CPUShares < linuxMinCPUShares {
			msg := fmt.Sprintf("Changing requested CPUShares of %d to minimum allowed of %d", hostConfig.CPUShares, linuxMinCPUShares)
			warnings = append(warnings, msg)
			logrus.Warnf(msg)
			hostConfig.CPUShares = linuxMinCPUShares
		} else if hostConfig.CPUShares > linuxMaxCPUShares {
			msg := fmt.Sprintf("Changing requested CPUShares of %d to maximum allowed of %d", hostConfig.CPUShares, linuxMaxCPUShares)
			warnings = append(warnings, msg)
			logrus.Warnf(msg)
			hostConfig.CPUShares = linuxMaxCPUShares
		}

		return
	}

}

func WithSecurityOpt(opts []string) Option {
	return func(c *Container) ([]string, error) {
		if c.HostConfig == nil {
			return nil, errors.Errorf("WithSecurityOpt() needs to be provided after WithHostConfig()")
		}

		c.HostConfig.SecurityOpt = append(c.HostConfig.SecurityOpt, opts...)
		return nil, nil
	}
}

func validatePlatformHostConfig(hostConfig *containertypes.HostConfig) (warnings []string, err error) {
	var (
		msg     string
		sysInfo = sysinfo.New(true)
	)

	warnings, err = verifyContainerResources(&hostConfig.Resources, sysInfo, false)
	if err != nil {
		return
	}

	if hostConfig.ShmSize < 0 {
		err = errors.Errorf("SHM size can not be less than 0")
		return
	}

	if hostConfig.OomScoreAdj < -1000 || hostConfig.OomScoreAdj > 1000 {
		err = errors.Errorf("Invalid value %d, range for oom score adj is [-1000, 1000]", hostConfig.OomScoreAdj)
		return
	}

	// ip-forwarding does not affect container with '--net=host' (or '--net=none')
	if sysInfo.IPv4ForwardingDisabled && !(hostConfig.NetworkMode.IsHost() || hostConfig.NetworkMode.IsNone()) {
		msg = "IPv4 forwarding is disabled. Networking will not work."
		warnings = append(warnings, msg)
		logrus.Warn(msg)
	}

	for dest := range hostConfig.Tmpfs {
		if err := volume.ValidateTmpfsMountDestination(dest); err != nil {
			return warnings, err
		}
	}

	if hostConfig.Memory > 0 && hostConfig.MemorySwap == 0 {
		// By default, MemorySwap is set to twice the size of Memory.
		hostConfig.MemorySwap = hostConfig.Memory * 2
	}

	if hostConfig.MemorySwappiness == nil {
		defaultSwappiness := int64(-1)
		hostConfig.MemorySwappiness = &defaultSwappiness
	}

	if hostConfig.OomKillDisable == nil {
		defaultOomKillDisable := false
		hostConfig.OomKillDisable = &defaultOomKillDisable
	}

	return
}

func validatePlatformContainerConfig(config *containertypes.Config) (warnings []string, err error) {
	return
}

func verifyContainerResources(resources *containertypes.Resources, sysInfo *sysinfo.SysInfo, update bool) ([]string, error) {
	warnings := []string{}

	// memory subsystem checks and adjustments
	if resources.Memory != 0 && resources.Memory < linuxMinMemory {
		return warnings, fmt.Errorf("Minimum memory limit allowed is 4MB")
	}
	if resources.Memory > 0 && !sysInfo.MemoryLimit {
		warnings = append(warnings, "Your kernel does not support memory limit capabilities or the cgroup is not mounted. Limitation discarded.")
		logrus.Warn("Your kernel does not support memory limit capabilities or the cgroup is not mounted. Limitation discarded.")
		resources.Memory = 0
		resources.MemorySwap = -1
	}
	if resources.Memory > 0 && resources.MemorySwap != -1 && !sysInfo.SwapLimit {
		warnings = append(warnings, "Your kernel does not support swap limit capabilities or the cgroup is not mounted. Memory limited without swap.")
		logrus.Warn("Your kernel does not support swap limit capabilities,or the cgroup is not mounted. Memory limited without swap.")
		resources.MemorySwap = -1
	}
	if resources.Memory > 0 && resources.MemorySwap > 0 && resources.MemorySwap < resources.Memory {
		return warnings, fmt.Errorf("Minimum memoryswap limit should be larger than memory limit, see usage")
	}
	if resources.Memory == 0 && resources.MemorySwap > 0 && !update {
		return warnings, fmt.Errorf("You should always set the Memory limit when using Memoryswap limit, see usage")
	}
	if resources.MemorySwappiness != nil && *resources.MemorySwappiness != -1 && !sysInfo.MemorySwappiness {
		warnings = append(warnings, "Your kernel does not support memory swappiness capabilities or the cgroup is not mounted. Memory swappiness discarded.")
		logrus.Warn("Your kernel does not support memory swappiness capabilities, or the cgroup is not mounted. Memory swappiness discarded.")
		resources.MemorySwappiness = nil
	}
	if resources.MemorySwappiness != nil {
		swappiness := *resources.MemorySwappiness
		if swappiness < -1 || swappiness > 100 {
			return warnings, fmt.Errorf("Invalid value: %v, valid memory swappiness range is 0-100", swappiness)
		}
	}
	if resources.MemoryReservation > 0 && !sysInfo.MemoryReservation {
		warnings = append(warnings, "Your kernel does not support memory soft limit capabilities or the cgroup is not mounted. Limitation discarded.")
		logrus.Warn("Your kernel does not support memory soft limit capabilities or the cgroup is not mounted. Limitation discarded.")
		resources.MemoryReservation = 0
	}
	if resources.MemoryReservation > 0 && resources.MemoryReservation < linuxMinMemory {
		return warnings, fmt.Errorf("Minimum memory reservation allowed is 4MB")
	}
	if resources.Memory > 0 && resources.MemoryReservation > 0 && resources.Memory < resources.MemoryReservation {
		return warnings, fmt.Errorf("Minimum memory limit can not be less than memory reservation limit, see usage")
	}
	if resources.KernelMemory > 0 && !sysInfo.KernelMemory {
		warnings = append(warnings, "Your kernel does not support kernel memory limit capabilities or the cgroup is not mounted. Limitation discarded.")
		logrus.Warn("Your kernel does not support kernel memory limit capabilities or the cgroup is not mounted. Limitation discarded.")
		resources.KernelMemory = 0
	}
	if resources.KernelMemory > 0 && resources.KernelMemory < linuxMinMemory {
		return warnings, fmt.Errorf("Minimum kernel memory limit allowed is 4MB")
	}
	if resources.KernelMemory > 0 && !kernel.CheckKernelVersion(4, 0, 0) {
		warnings = append(warnings, "You specified a kernel memory limit on a kernel older than 4.0. Kernel memory limits are experimental on older kernels, it won't work as expected and can cause your system to be unstable.")
		logrus.Warn("You specified a kernel memory limit on a kernel older than 4.0. Kernel memory limits are experimental on older kernels, it won't work as expected and can cause your system to be unstable.")
	}
	if resources.OomKillDisable != nil && !sysInfo.OomKillDisable {
		// only produce warnings if the setting wasn't to *disable* the OOM Kill; no point
		// warning the caller if they already wanted the feature to be off
		if *resources.OomKillDisable {
			warnings = append(warnings, "Your kernel does not support OomKillDisable. OomKillDisable discarded.")
			logrus.Warn("Your kernel does not support OomKillDisable. OomKillDisable discarded.")
		}
		resources.OomKillDisable = nil
	}

	if resources.PidsLimit != 0 && !sysInfo.PidsLimit {
		warnings = append(warnings, "Your kernel does not support pids limit capabilities or the cgroup is not mounted. PIDs limit discarded.")
		logrus.Warn("Your kernel does not support pids limit capabilities or the cgroup is not mounted. PIDs limit discarded.")
		resources.PidsLimit = 0
	}

	// cpu subsystem checks and adjustments
	if resources.NanoCPUs > 0 && resources.CPUPeriod > 0 {
		return warnings, fmt.Errorf("Conflicting options: Nano CPUs and CPU Period cannot both be set")
	}
	if resources.NanoCPUs > 0 && resources.CPUQuota > 0 {
		return warnings, fmt.Errorf("Conflicting options: Nano CPUs and CPU Quota cannot both be set")
	}
	if resources.NanoCPUs > 0 && (!sysInfo.CPUCfsPeriod || !sysInfo.CPUCfsQuota) {
		return warnings, fmt.Errorf("NanoCPUs can not be set, as your kernel does not support CPU cfs period/quota or the cgroup is not mounted")
	}
	// The highest precision we could get on Linux is 0.001, by setting
	//   cpu.cfs_period_us=1000ms
	//   cpu.cfs_quota=1ms
	// See the following link for details:
	// https://www.kernel.org/doc/Documentation/scheduler/sched-bwc.txt
	// Here we don't set the lower limit and it is up to the underlying platform (e.g., Linux) to return an error.
	// The error message is 0.01 so that this is consistent with Windows
	if resources.NanoCPUs < 0 || resources.NanoCPUs > int64(sysinfo.NumCPU())*1e9 {
		return warnings, fmt.Errorf("Range of CPUs is from 0.01 to %d.00, as there are only %d CPUs available", sysinfo.NumCPU(), sysinfo.NumCPU())
	}

	if resources.CPUShares > 0 && !sysInfo.CPUShares {
		warnings = append(warnings, "Your kernel does not support CPU shares or the cgroup is not mounted. Shares discarded.")
		logrus.Warn("Your kernel does not support CPU shares or the cgroup is not mounted. Shares discarded.")
		resources.CPUShares = 0
	}
	if resources.CPUPeriod > 0 && !sysInfo.CPUCfsPeriod {
		warnings = append(warnings, "Your kernel does not support CPU cfs period or the cgroup is not mounted. Period discarded.")
		logrus.Warn("Your kernel does not support CPU cfs period or the cgroup is not mounted. Period discarded.")
		resources.CPUPeriod = 0
	}
	if resources.CPUPeriod != 0 && (resources.CPUPeriod < 1000 || resources.CPUPeriod > 1000000) {
		return warnings, fmt.Errorf("CPU cfs period can not be less than 1ms (i.e. 1000) or larger than 1s (i.e. 1000000)")
	}
	if resources.CPUQuota > 0 && !sysInfo.CPUCfsQuota {
		warnings = append(warnings, "Your kernel does not support CPU cfs quota or the cgroup is not mounted. Quota discarded.")
		logrus.Warn("Your kernel does not support CPU cfs quota or the cgroup is not mounted. Quota discarded.")
		resources.CPUQuota = 0
	}
	if resources.CPUQuota > 0 && resources.CPUQuota < 1000 {
		return warnings, fmt.Errorf("CPU cfs quota can not be less than 1ms (i.e. 1000)")
	}
	if resources.CPUPercent > 0 {
		warnings = append(warnings, fmt.Sprintf("%s does not support CPU percent. Percent discarded.", runtime.GOOS))
		logrus.Warnf("%s does not support CPU percent. Percent discarded.", runtime.GOOS)
		resources.CPUPercent = 0
	}

	// cpuset subsystem checks and adjustments
	if (resources.CpusetCpus != "" || resources.CpusetMems != "") && !sysInfo.Cpuset {
		warnings = append(warnings, "Your kernel does not support cpuset or the cgroup is not mounted. Cpuset discarded.")
		logrus.Warn("Your kernel does not support cpuset or the cgroup is not mounted. Cpuset discarded.")
		resources.CpusetCpus = ""
		resources.CpusetMems = ""
	}
	cpusAvailable, err := sysInfo.IsCpusetCpusAvailable(resources.CpusetCpus)
	if err != nil {
		return warnings, fmt.Errorf("Invalid value %s for cpuset cpus", resources.CpusetCpus)
	}
	if !cpusAvailable {
		return warnings, fmt.Errorf("Requested CPUs are not available - requested %s, available: %s", resources.CpusetCpus, sysInfo.Cpus)
	}
	memsAvailable, err := sysInfo.IsCpusetMemsAvailable(resources.CpusetMems)
	if err != nil {
		return warnings, fmt.Errorf("Invalid value %s for cpuset mems", resources.CpusetMems)
	}
	if !memsAvailable {
		return warnings, fmt.Errorf("Requested memory nodes are not available - requested %s, available: %s", resources.CpusetMems, sysInfo.Mems)
	}

	// blkio subsystem checks and adjustments
	if resources.BlkioWeight > 0 && !sysInfo.BlkioWeight {
		warnings = append(warnings, "Your kernel does not support Block I/O weight or the cgroup is not mounted. Weight discarded.")
		logrus.Warn("Your kernel does not support Block I/O weight or the cgroup is not mounted. Weight discarded.")
		resources.BlkioWeight = 0
	}
	if resources.BlkioWeight > 0 && (resources.BlkioWeight < 10 || resources.BlkioWeight > 1000) {
		return warnings, fmt.Errorf("Range of blkio weight is from 10 to 1000")
	}
	if resources.IOMaximumBandwidth != 0 || resources.IOMaximumIOps != 0 {
		return warnings, fmt.Errorf("Invalid QoS settings: %s does not support Maximum IO Bandwidth or Maximum IO IOps", runtime.GOOS)
	}
	if len(resources.BlkioWeightDevice) > 0 && !sysInfo.BlkioWeightDevice {
		warnings = append(warnings, "Your kernel does not support Block I/O weight_device or the cgroup is not mounted. Weight-device discarded.")
		logrus.Warn("Your kernel does not support Block I/O weight_device or the cgroup is not mounted. Weight-device discarded.")
		resources.BlkioWeightDevice = []*pblkiodev.WeightDevice{}
	}
	if len(resources.BlkioDeviceReadBps) > 0 && !sysInfo.BlkioReadBpsDevice {
		warnings = append(warnings, "Your kernel does not support BPS Block I/O read limit or the cgroup is not mounted. Block I/O BPS read limit discarded.")
		logrus.Warn("Your kernel does not support BPS Block I/O read limit or the cgroup is not mounted. Block I/O BPS read limit discarded")
		resources.BlkioDeviceReadBps = []*pblkiodev.ThrottleDevice{}
	}
	if len(resources.BlkioDeviceWriteBps) > 0 && !sysInfo.BlkioWriteBpsDevice {
		warnings = append(warnings, "Your kernel does not support BPS Block I/O write limit or the cgroup is not mounted. Block I/O BPS write limit discarded.")
		logrus.Warn("Your kernel does not support BPS Block I/O write limit or the cgroup is not mounted. Block I/O BPS write limit discarded.")
		resources.BlkioDeviceWriteBps = []*pblkiodev.ThrottleDevice{}
	}
	if len(resources.BlkioDeviceReadIOps) > 0 && !sysInfo.BlkioReadIOpsDevice {
		warnings = append(warnings, "Your kernel does not support IOPS Block read limit or the cgroup is not mounted. Block I/O IOPS read limit discarded.")
		logrus.Warn("Your kernel does not support IOPS Block I/O read limit in IO or the cgroup is not mounted. Block I/O IOPS read limit discarded.")
		resources.BlkioDeviceReadIOps = []*pblkiodev.ThrottleDevice{}
	}
	if len(resources.BlkioDeviceWriteIOps) > 0 && !sysInfo.BlkioWriteIOpsDevice {
		warnings = append(warnings, "Your kernel does not support IOPS Block write limit or the cgroup is not mounted. Block I/O IOPS write limit discarded.")
		logrus.Warn("Your kernel does not support IOPS Block I/O write limit or the cgroup is not mounted. Block I/O IOPS write limit discarded.")
		resources.BlkioDeviceWriteIOps = []*pblkiodev.ThrottleDevice{}
	}

	return warnings, nil
}

func (container *Container) setSecurityOption(opts []string) error {
	var (
		labelOpts []string
		err       error
	)

	for _, opt := range container.HostConfig.SecurityOpt {
		if opt == "no-new-privileges" {
			container.NoNewPrivileges = true
			continue
		}

		var con []string
		if strings.Contains(opt, "=") {
			con = strings.SplitN(opt, "=", 2)
		} else if strings.Contains(opt, ":") {
			con = strings.SplitN(opt, ":", 2)
			logrus.Warn("Security options with `:` as a separator are deprecated and will be completely unsupported in 1.14, use `=` instead.")
		}

		if len(con) != 2 {
			return fmt.Errorf("invalid --security-opt 1: %q", opt)
		}

		switch con[0] {
		case "label":
			labelOpts = append(labelOpts, con[1])
		case "apparmor":
			container.AppArmorProfile = con[1]
		case "seccomp":
			container.SeccompProfile = con[1]
		default:
			return fmt.Errorf("invalid --security-opt 2: %q", opt)
		}
	}

	container.ProcessLabel, container.MountLabel, err = label.InitLabels(labelOpts)
	return err
}
