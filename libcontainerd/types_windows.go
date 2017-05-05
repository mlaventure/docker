package libcontainerd

import "github.com/Microsoft/hcsshim"

// Process contains information about a running process within a container
type Process struct {
	Pid uint32
}

// Stats contains statistics from HCS
type Stats hcsshim.Statistics

// Resources defines updatable container resource values.
type Resources struct{}

// ServicingOption is a CreateOption with a no-op application that signifies
// the container needs to be used for a Windows servicing operation.
type ServicingOption struct {
	IsServicing bool
}

// FlushOption is a CreateOption that signifies if the container should be
// started with flushes ignored until boot has completed. This is an optimisation
// for first boot of a container.
type FlushOption struct {
	IgnoreFlushesDuringBoot bool
}

// HyperVIsolationOption is a CreateOption that indicates whether the runtime
// should start the container as a Hyper-V container.
type HyperVIsolationOption struct {
	IsHyperV bool
}

// LayerOption is a CreateOption that indicates to the runtime the layer folder
// and layer paths for a container.
type LayerOption struct {
	// LayerFolderPath is the path to the current layer folder. Empty for Hyper-V containers.
	LayerFolderPath string `json:",omitempty"`
	// Layer paths of the parent layers
	LayerPaths []string
}

// NetworkEndpointsOption is a CreateOption that provides the runtime list
// of network endpoints to which a container should be attached during its creation.
type NetworkEndpointsOption struct {
	Endpoints                []string
	AllowUnqualifiedDNSQuery bool
	DNSSearchList            []string
	NetworkSharedContainerID string
}

// CredentialsOption is a CreateOption that indicates the credentials from
// a credential spec to be used to the runtime
type CredentialsOption struct {
	Credentials string
}

// Checkpoint holds the details of a checkpoint (not supported in windows)
type Checkpoint struct {
	Name string
}

// Checkpoints contains the details of a checkpoint
type Checkpoints struct {
	Checkpoints []*Checkpoint
}
