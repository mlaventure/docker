package libcontainerd

// Process contains information about a running process within a container
type Process ProcessCommon

// Stats contains a stats properties from containerd. // TODO: stats type must be updated, probably a map[string]interface{} ?
type Stats struct{}

// Resources defines updatable container resource values. TODO: it must match containerd upcoming API
type Resources struct{}

// Checkpoints contains the details of a checkpoint
type Checkpoints struct{}
