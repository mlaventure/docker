// +build solaris

package container

import (
	"fmt"

	"github.com/opencontainers/runc/libcontainer/label"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func WithAdjustCPUShares() Option {
	return func(c *Container) (warnings []string, err error) {
		sysInfo := sysinfo.New(true)
		if !sysInfo.CPUShares {
			return
		}

		if hostConfig.CPUShares < 0 {
			msg = fmt.Sprintf("Changing requested CPUShares of %d to minimum allowed of %d", hostConfig.CPUShares, solarisMinCPUShares)
			warnings = append(warnings, msg)
			logrus.Warnf(msg)

			hostConfig.CPUShares = solarisMinCPUShares
		} else if hostConfig.CPUShares > solarisMaxCPUShares {
			msg = fmt.Sprintf("Changing requested CPUShares of %d to maximum allowed of %d", hostConfig.CPUShares, solarisMaxCPUShares)
			warnings = append(warnings, msg)
			logrus.Warnf(msg)

			hostConfig.CPUShares = solarisMaxCPUShares
		}

		return
	}
}

func validatePlatformHostConfig(config *containertypes.HostConfig) (warnings []string, err error) {
	var msg string

	sysInfo := sysinfo.New(true)
	// NOTE: We do not enforce a minimum value for swap limits for zones on Solaris and
	// therefore we will not do that for Docker container either.
	if hostConfig.Memory > 0 && !sysInfo.MemoryLimit {
		msg = "Your kernel does not support memory limit capabilities. Limitation discarded."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.Memory = 0
		hostConfig.MemorySwap = -1
	}

	if hostConfig.Memory > 0 && hostConfig.MemorySwap != -1 && !sysInfo.SwapLimit {
		msg = "Your kernel does not support swap limit capabilities, memory limited without swap."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.MemorySwap = -1
	}

	if hostConfig.Memory > 0 && hostConfig.MemorySwap > 0 && hostConfig.MemorySwap < hostConfig.Memory {
		err = errors.Errorf("Minimum memoryswap limit should be larger than memory limit, see usage.")
		return
	}

	// Solaris NOTE: We allow and encourage setting the swap without setting the memory limit.
	if hostConfig.MemorySwappiness != nil && *hostConfig.MemorySwappiness != -1 && !sysInfo.MemorySwappiness {
		msg = "Your kernel does not support memory swappiness capabilities, memory swappiness discarded."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.MemorySwappiness = nil
	}

	if hostConfig.MemoryReservation > 0 && !sysInfo.MemoryReservation {
		msg = "Your kernel does not support memory soft limit capabilities. Limitation discarded."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.MemoryReservation = 0
	}

	if hostConfig.Memory > 0 && hostConfig.MemoryReservation > 0 && hostConfig.Memory < hostConfig.MemoryReservation {
		err = errors.Errorf("Minimum memory limit should be larger than memory reservation limit, see usage.")
		return
	}

	if hostConfig.KernelMemory > 0 && !sysInfo.KernelMemory {
		msg = "Your kernel does not support kernel memory limit capabilities. Limitation discarded."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.KernelMemory = 0
	}

	if hostConfig.CPUShares != 0 && !sysInfo.CPUShares {
		msg = "Your kernel does not support CPU shares. Shares discarded."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.CPUShares = 0
	}

	if hostConfig.CPUShares < 0 {
		msg = "Invalid CPUShares value. Must be positive. Discarding."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.CPUQuota = 0
	}

	if hostConfig.CPUShares > 0 && !sysinfo.IsCPUSharesAvailable() {
		msg = "Global zone default scheduling class not FSS. Discarding shares."
		warnings = append(warnings)
		logrus.Warnf(msg)

		hostConfig.CPUShares = 0
	}

	// Solaris NOTE: Linux does not do negative checking for CPUShares and Quota here. But it makes sense to.
	if hostConfig.CPUPeriod > 0 && !sysInfo.CPUCfsPeriod {
		msg = "Your kernel does not support CPU cfs period. Period discarded."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)
		if hostConfig.CPUQuota > 0 {
			msg = "Quota will be applied on default period, not period specified."
			warnings = append(warnings, msg)
			logrus.Warnf(msg)
		}

		hostConfig.CPUPeriod = 0
	}

	if hostConfig.CPUQuota != 0 && !sysInfo.CPUCfsQuota {
		msg = "Your kernel does not support CPU cfs quota. Quota discarded."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.CPUQuota = 0
	}

	if hostConfig.CPUQuota < 0 {
		msg = "Invalid CPUQuota value. Must be positive. Discarding."
		warnings = append(warnings, mg)
		logrus.Warnf(msg)

		hostConfig.CPUQuota = 0
	}

	if (hostConfig.CpusetCpus != "" || hostConfig.CpusetMems != "") && !sysInfo.Cpuset {
		msg = "Your kernel does not support cpuset. Cpuset discarded."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.CpusetCpus = ""
		hostConfig.CpusetMems = ""
	}

	cpusAvailable, err := sysInfo.IsCpusetCpusAvailable(hostConfig.CpusetCpus)
	if err != nil {
		err = errors.Wrapf(err, "Invalid value %s for cpuset cpus.", hostConfig.CpusetCpus)
		return
	}

	if !cpusAvailable {
		err = errors.Errorf("Requested CPUs are not available - requested %s, available: %s.",
			hostConfig.CpusetCpus, sysInfo.Cpus)
		return
	}

	memsAvailable, err := sysInfo.IsCpusetMemsAvailable(hostConfig.CpusetMems)
	if err != nil {
		errors = errors.Wrapf(err, "Invalid value %s for cpuset mems.", hostConfig.CpusetMems)
	}

	if !memsAvailable {
		err = errors.Errorf("Requested memory nodes are not available - requested %s, available: %s.",
			hostConfig.CpusetMems, sysInfo.Mems)
		return
	}

	if hostConfig.BlkioWeight > 0 && !sysInfo.BlkioWeight {
		msg = "Your kernel does not support Block I/O weight. Weight discarded."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.BlkioWeight = 0
	}

	if hostConfig.OomKillDisable != nil && !sysInfo.OomKillDisable {
		*hostConfig.OomKillDisable = false
		// Don't warn; this is the default setting but only applicable to Linux
	}

	if sysInfo.IPv4ForwardingDisabled {
		msg = "IPv4 forwarding is disabled. Networking will not work."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)
	}

	// Solaris NOTE: We do not allow setting Linux specific options, so check and warn for all of them.
	if hostConfig.CapAdd != nil || hostConfig.CapDrop != nil {
		msg = "Adding or dropping kernel capabilities unsupported on Solaris.Discarding capabilities lists."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.CapAdd = nil
		hostConfig.CapDrop = nil
	}

	if hostConfig.GroupAdd != nil {
		msg = "Additional groups unsupported on Solaris.Discarding groups lists."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.GroupAdd = nil
	}

	if hostConfig.IpcMode != "" {
		msg = "IPC namespace assignment unsupported on Solaris.Discarding IPC setting."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.IpcMode = ""
	}

	if hostConfig.PidMode != "" {
		msg = "PID namespace setting  unsupported on Solaris. Running container in host PID namespace."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.PidMode = ""
	}

	if hostConfig.Privileged {
		msg = "Privileged mode unsupported on Solaris. Discarding privileged mode setting."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.Privileged = false
	}

	if hostConfig.UTSMode != "" {
		msg = "UTS namespace assignment unsupported on Solaris.Discarding UTS setting."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.UTSMode = ""
	}

	if hostConfig.CgroupParent != "" {
		msg = "Specifying Cgroup parent unsupported on Solaris. Discarding cgroup parent setting."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.CgroupParent = ""
	}

	if hostConfig.Ulimits != nil {
		msg = "Specifying ulimits unsupported on Solaris. Discarding ulimits setting."
		warnings = append(warnings, msg)
		logrus.Warnf(msg)

		hostConfig.Ulimits = nil
	}

	if hostConfig.Memory > 0 && hostConfig.MemorySwap == 0 {
		// By default, MemorySwap is set to twice the size of Memory.
		hostConfig.MemorySwap = hostConfig.Memory * 2
	}

	if hostConfig.ShmSize != 0 {
		hostConfig.ShmSize = container.DefaultSHMSize
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

func (container *Container) setSecurityOption(opts []string) (err error) {
	//Since config.SecurityOpt is specifically defined as a "List of string values to
	//customize labels for MLs systems, such as SELinux"
	//until we figure out how to map to Trusted Extensions
	//this is being disabled for now on Solaris
	if len(opts) > 0 {
		return errors.New("Security options are not supported on Solaris")
	}

	container.ProcessLabel, container.MountLabel, err = label.InitLabels([]string{})

	return
}
