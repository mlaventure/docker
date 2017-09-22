package libcontainerd

type liberr struct {
	msg string
}

func (e liberr) Error() string {
	return e.msg
}

type notFound struct {
	liberr
}

func (notFound) NotFound() {}

func newNotFoundError(err string) error { return notFound{liberr{err}} }

type invalidParam struct {
	liberr
}

func (invalidParam) InvalidParameter() {}

func newInvalidParameterError(err string) error { return invalidParam{liberr{err}} }

type notImpl struct {
	liberr
}

func (notImpl) NotImplemented() {}

func newNotImplementedError(err string) error { return notImpl{liberr{err}} }

type conflict struct {
	liberr
}

func (conflict) Conflict() {}

func newConflictError(err string) error { return conflict{liberr{err}} }
