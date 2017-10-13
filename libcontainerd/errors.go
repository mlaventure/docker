package libcontainerd

import "errors"

type liberr struct {
	err error
}

func (e liberr) Error() string {
	return e.err.Error()
}

func (e liberr) Cause() error {
	return e.err
}

type notFoundErr struct {
	liberr
}

func (notFoundErr) NotFound() {}

func newNotFoundError(err string) error { return notFoundErr{liberr{errors.New(err)}} }
func wrapNotFoundError(err error) error { return notFoundErr{liberr{err}} }

type invalidParamErr struct {
	liberr
}

func (invalidParamErr) InvalidParameter() {}

func newInvalidParameterError(err string) error { return invalidParamErr{liberr{errors.New(err)}} }

type notImplErr struct {
	liberr
}

func (notImplErr) NotImplemented() {}

func newNotImplementedError(err string) error { return notImplErr{liberr{errors.New(err)}} }

type conflictErr struct {
	liberr
}

func (conflictErr) ConflictErr() {}

func newConflictError(err string) error { return conflictErr{liberr{errors.New(err)}} }

type sysErr struct {
	liberr
}

func newSystemError(err string) error { return sysErr{liberr{errors.New(err)}} }
func wrapSystemError(err error) error { return sysErr{liberr{err}} }
