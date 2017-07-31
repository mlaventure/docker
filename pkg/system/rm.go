package system

import (
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/docker/docker/pkg/mount"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// EnsureRemoveAll wraps `os.RemoveAll` to check for specific errors that can
// often be remedied.
// Only use `EnsureRemoveAll` if you really want to make every effort to remove
// a directory.
//
// Because of the way `os.Remove` (and by extension `os.RemoveAll`) works, there
// can be a race between reading directory entries and then actually attempting
// to remove everything in the directory.
// These types of errors do not need to be returned since it's ok for the dir to
// be gone we can just retry the remove operation.
//
// This should not return a `os.ErrNotExist` kind of error under any circumstances
func EnsureRemoveAll(dir string) error {
	notExistErr := make(map[string]bool)

	// track retries
	exitOnErr := make(map[string]int)
	maxRetry := 5

	// Attempt to unmount anything beneath this dir first
	mount.RecursiveUnmount(dir)

	for {
		err := os.RemoveAll(dir)
		if err == nil {
			return err
		}

		pe, ok := err.(*os.PathError)
		if !ok {
			logrus.Debugf("EnsureRemoveAll (not PathError): dir: %s, %#v", dir, err)
			return err
		}

		if os.IsNotExist(err) {
			if notExistErr[pe.Path] {
				logrus.Debugf("EnsureRemoveAll (not exist): path: %v: %v", pe.Path, err)
				return err
			}
			notExistErr[pe.Path] = true

			// There is a race where some subdir can be removed but after the parent
			//   dir entries have been read.
			// So the path could be from `os.Remove(subdir)`
			// If the reported non-existent path is not the passed in `dir` we
			// should just retry, but otherwise return with no error.
			if pe.Path == dir {
				return nil
			}
			continue
		}

		if pe.Err != syscall.EBUSY {
			logrus.Debugf("EnsureRemoveAll (not ebusy): path: %v: %v", pe.Path, err)
			return err
		}

		if mounted, _ := mount.Mounted(pe.Path); mounted {
			if e := mount.Unmount(pe.Path); e != nil {
				if mounted, _ := mount.Mounted(pe.Path); mounted {
					return errors.Wrapf(e, "error while removing %s", dir)
				}
			}
		}

		if exitOnErr[pe.Path] == maxRetry {
			logrus.Debugf("EnsureRemoveAll (maxRetry reached): path: %v: %v", pe.Path, err)
			out, err1 := exec.Command("lsof", "+D", pe.Path).CombinedOutput()
			logrus.Debugf("LSOF %s output: %v\n %s", pe.Path, err1, string(out))
			return err
		}
		exitOnErr[pe.Path]++
		time.Sleep(100 * time.Millisecond)
	}
}
