// +build linux,cgo,!static_build,journald

package journald

import (
	"context"
	"io"
	"strconv"
	"syscall"
	"time"

	"github.com/coreos/go-systemd/journal"
	"github.com/coreos/go-systemd/sdjournal"
	"github.com/docker/docker/daemon/logger"
	"github.com/pkg/errors"
)

var newJournal = sdjournal.NewJournal

type Journal interface {
	AddMatch(match string) error
	SetDataThreshold(threshold uint64) error

	SeekHead() error
	SeekTail() error
	PreviousSkip(skip uint64) (uint64, error)

	Next() (uint64, error)
	Previous() (uint64, error)
	GetEntry() (*sdjournal.JournalEntry, error)
	GetRealtimeUsec() (uint64, error)
	SeekRealtimeUsec(usec uint64) error

	Wait(timeout time.Duration) int

	Close() error
}

func (s *journald) Close() error {
	s.mu.Lock()
	for _, r := range s.readers {
		r.Close()
	}
	s.mu.Unlock()
	return nil
}

func (s *journald) ReadLogs(config logger.ReadConfig) *logger.LogWatcher {
	logWatcher := logger.NewLogWatcher()
	go s.readLogs(logWatcher, config)
	return logWatcher
}

func (s *journald) readLogs(logWatcher *logger.LogWatcher, config logger.ReadConfig) {
	var (
		j   Journal
		err error
	)

	defer func() {
		if err != nil {
			logWatcher.Err <- err
		}
		close(logWatcher.Msg)
	}()

	j, err = newSDJournal(logWatcher, config, "CONTAINER_ID_FULL="+s.vars["CONTAINER_ID_FULL"])
	if err != nil {
		return
	}
	defer j.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-logWatcher.WatchClose()
		cancel()
	}()

	if config.Follow {
		s.mu.Lock()
		s.readers = append(s.readers, logWatcher)
		s.mu.Unlock()
	}

	for {
		err = readAllEntries(ctx, j, logWatcher)
		if err != nil && err != io.EOF {
			return
		}

		if !config.Follow || err == nil {
			err = nil // it may be io.EOF
			return
		}

		// We need to wait for new entries
		event := sdjournal.SD_JOURNAL_NOP
		for event == sdjournal.SD_JOURNAL_NOP {
			select {
			case <-ctx.Done():
				return
			default:
				event = j.Wait(time.Duration(1 * time.Second))
				if event < 0 {
					err = errors.Errorf("error while waiting for new entries, errno: %v", syscall.Errno(-event))
					return
				}
			}
		}
	}
}

func newSDJournal(logWatcher *logger.LogWatcher, config logger.ReadConfig, match string) (j Journal, err error) {
	if j, err = newJournal(); err != nil {
		err = errors.Wrap(err, "failed to open journal")
		return
	}
	defer func() {
		if err != nil {
			j.Close()
		}
	}()

	if err = j.SetDataThreshold(0); err != nil {
		err = errors.Wrap(err, "failed to set journal data threshold")
		return
	}

	if err = j.AddMatch(match); err != nil {
		err = errors.Wrap(err, "failed to set journal match")
		return
	}

	if config.Tail > 0 {
		if err = j.SeekTail(); err != nil {
			err = errors.Wrap(err, "failed to seek to end of journal")
			return
		}

		var skip, target uint64
		target = uint64(config.Tail + 1)
		if skip, err = j.PreviousSkip(target); err != nil {
			err = errors.Wrap(err, "failed to skip tail entries")
			return
		}

		// If we made it to the beginning of the journal, reset the
		// head so the next read gets the first line
		if skip != target {
			if err = j.SeekHead(); err != nil {
				err = errors.Wrap(err, "failed to seek to journal start")
				return
			}
		}

		// If we have a timestamp check that we are honoring it
		if !config.Since.IsZero() {
			sinceTs := uint64(config.Since.UnixNano() / 1000)
			if sinceTs != 0 {
				var (
					usec uint64
					more uint64
				)

				more, err = j.Next()
				if err != nil {
					err = errors.Wrap(err, "failed to advance to next entry while checking tail timestamp")
					return
				}

				if more != 0 {
					if usec, err = j.GetRealtimeUsec(); err != nil {
						err = errors.Wrap(err, "failed to get current entry timestamp")
						return
					}

					if usec < sinceTs {
						if err = j.SeekRealtimeUsec(sinceTs); err != nil {
							err = errors.Wrapf(err, "failed to seek to time %v", config.Since)
							return
						}
					} else {
						// timestamp is all good, go back where we were
						_, err = j.Previous()
						if err != nil {
							err = errors.Wrap(err, "failed to advance to previous entry")
							return
						}
					}
				}
			}
		}
	} else {
		if err = j.SeekHead(); err != nil {
			err = errors.Wrap(err, "failed to seek to journal start")
			return
		}

		// If we have a timestamp honor it
		if !config.Since.IsZero() {
			sinceTs := uint64(config.Since.UnixNano() / 1000)
			if sinceTs != 0 {
				if err = j.SeekRealtimeUsec(sinceTs); err != nil {
					err = errors.Wrapf(err, "failed to seek to time %v", config.Since)
					return
				}
			}
		}
	}

	return
}

var knownFields = map[string]struct{}{
	"MESSAGE":           struct{}{},
	"MESSAGE_ID":        struct{}{},
	"PRIORITY":          struct{}{},
	"CODE_FILE":         struct{}{},
	"CODE_LINE":         struct{}{},
	"CODE_FUNC":         struct{}{},
	"ERRNO":             struct{}{},
	"SYSLOG_FACILITY":   struct{}{},
	"SYSLOG_IDENTIFIER": struct{}{},
	"SYSLOG_PID":        struct{}{},
	"CONTAINER_NAME":    struct{}{},
	"CONTAINER_ID":      struct{}{},
	"CONTAINER_ID_FULL": struct{}{},
	"CONTAINER_TAG":     struct{}{},
}

func readAllEntries(ctx context.Context, j Journal, logWatcher *logger.LogWatcher) error {
	for {
		select {
		case <-ctx.Done():
			// TODO: test for regression: https://github.com/docker/docker/pull/29863
			return nil
		default:
			// go on and read next entry
		}

		more, err := j.Next()
		if err != nil {
			return errors.Wrap(err, "failed to advance to next entry")
		}

		if more == 0 {
			return io.EOF
		}

		ent, err := j.GetEntry()
		if err != nil {
			return errors.Wrap(err, "failed to get journal entry")
		}

		attrs := make(map[string]string)
		for k, v := range ent.Fields {
			if k[0] == '_' {
				continue
			}
			if _, ok := knownFields[k]; !ok {
				attrs[k] = v
			}
		}

		source := ""
		if prioStr := ent.Fields["PRIORITY"]; prioStr != "" {
			prio, err := strconv.Atoi(prioStr)
			switch {
			case err != nil:
				// ignore
			case prio == int(journal.PriErr):
				source = "stderr"
			case prio == int(journal.PriInfo):
				source = "stdout"
			}
		}

		line := ent.Fields["MESSAGE"]
		if _, ok := ent.Fields["CONTAINER_PARTIAL_MESSAGE"]; !ok {
			line += "\n"
		}

		logWatcher.Msg <- &logger.Message{
			Line:      []byte(line),
			Source:    source,
			Timestamp: time.Unix(int64(ent.RealtimeTimestamp)/1000000, (int64(ent.RealtimeTimestamp)%1000000)*1000),
			Attrs:     attrs,
		}
	}
}
