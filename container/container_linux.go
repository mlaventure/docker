package container

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func detachMounted(path string) error {
	err := unix.Unmount(path, unix.MNT_EXPIRE)
	if err == unix.EAGAIN {
		logrus.Debugf("[c] %s: is expired", path)
		return unix.Unmount(path, unix.MNT_EXPIRE)
	}
	logrus.WithError(err).Debugf("[c] %s: is busy", path)
	return unix.Unmount(path, unix.MNT_DETACH)
}
