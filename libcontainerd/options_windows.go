package libcontainerd

// CreateOption allows to configure parameters of container creation.
type CreateOption interface {
	Apply(*WindowsCreateRequest) error
}

func WithRuntime(name string) CreateOption {
	return runtime(name)
}

type runtime string

func (r runtime) Apply(wcr *WindowsCreateRequest) error {
	wcr.cr.Runtime = string(r)
	return nil
}
