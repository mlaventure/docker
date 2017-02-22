// build +linux

package journald

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-systemd/sdjournal"
	"github.com/docker/docker/daemon/logger"
	"github.com/pkg/errors"
)

func TestReadLogs(t *testing.T) {
	newJournalBackup = newJournal
	newJournal = func() Journal {
		j, err := newTestJournal(filepath.Join("testdata", "seq.json-pretty"))
		if err != nil {
			t.Error(err)
		}
		return j
	}
	defer func() {
		newJournal = newJournalBackup
	}()

	j := &journald{
		readers: []*logger.LogWatcher{},
	}
}

func newTestJournal(file string) (Journal, error) {

	j := &testJournal{
		entries: make([]map[string]string),
	}

	f, err := os.OpenFile(file, os.RDONLY, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open journal")
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	for {
		var v map[string]string
		err := dec.Decode(&v)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrapf(err, "failed to decode json entry %d", len(j.entries))
		}
		j.entries = append(j.entries, v)
	}

	return j, nil
}

type testJournal struct {
	entries    []map[string]string
	pos        int64
	matchKey   string
	matchValue string
}

func (j *testJournal) AddMatch(match string) error {
	if j.matchKey == "" {
		parts := strings.Split(match, "=")
		if len(parts) != 2 || len(parts[0]) == 0 {
			return errors.Errorf("invalid match string: %q", match)
		}
		j.matchKey = parts[0]
		j.matchValue = parts[1]
		return nil
	}
	return errors.Errorf("match is already set to '%s=%s'", j.matchKey, j.matchValue)
}

func (j *testJournal) SetDataThreshold(threshold uint64) error {
	// Just ignore it, we never set its to something else than 0 anyway
	return nil
}

func (j *testJournal) SeekHead() error {
	j.pos = -1
	return nil
}

func (j *testJournal) SeekTail() error {
	j.pos = len(j.entries)
	return nil
}

func (j *testJournal) PreviousSkip(skip uint64) (uint64, error) {
	j.pos = j.pos - skip
	if j.pos < 0 {
		j.pos == -1
	}
	return 0, nil
}

func (j *testJournal) Next() (uint64, error) {
	if j.pos == len(j.entries) {
		return 0, io.EOF
	}

	j.pos += 1
	if j.pos == len(j.entries) {
		return 0, nil
	}

	return 1, nil
}

func (j *testJournal) Previous() (uint64, error) {
	if j.pos == -1 {
		return 0, io.EOF
	}

	j.pos -= 1
	if j.pos == -1 {
		return 0, nil
	}

	return 1, nil
}
func (j *testJournal) GetEntry() (*sdjournal.JournalEntry, error) {
	if j.pos < 0 || j.pos >= len(j.entries) {
		return nil, errors.New("invalid offset")
	}

	je := &sdjournal.JournalEntry{
		Fields: make(map[string]string),
	}
	for k, v := range j.entries[j.pos] {
		switch k {
		case "__CURSOR":
			je.Cursor = v
		case "__REALTIME_TIMESTAMP":
			ts, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse realtime tiestamp")
			}
			je.RealtimeTimestamp = ts
		case "__MONOTONIC_TIMESTAMP":
			ts, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, errors.Wrapf(err, "failed to parse realtime tiestamp")
			}
			je.MonotonicTimestamp = ts
		case strings.HasPrefix("__", v):
			return errors.Errorf("unknown field %q", k)
		default:
			je.Fields[k] = v
		}
	}

	return je, nil
}
func (j *testJournal) GetRealtimeUsec() (uint64, error) {
	if j.pos < 0 || j.pos >= len(j.entries) {
		return nil, errors.New("invalid offset")
	}

	rts, ok := j.entries[j.pos]["__REALTIME_TIMESTAMP"]
	if !ok {
		return 0, errors.Errorf("invalid entry %d (no realtime timestamp)", j.pos)
	}

	return strconv.ParseUint(rts, 10, 64)
}

func (j *testJournal) SeekRealtimeUsec(usec uint64) error {
	j.SeekHead()

	for {
		pos, err := j.Next()
		if pos == 0 || err == io.EOF {
			return nil
		}

		ts, err := j.GetRealtimeUsec()
		if err != nil {
			return err
		}

		if usec >= ts {
			break
		}
	}

	return nil

}
func (j *testJournal) Wait(timeout time.Duration) int {
	if j.pos == -1 {
		return sdjournal.SD_JOURNAL_APPEND
	}
	time.Sleep(timeout)
	return sdjournal.SD_JOURNAL_NOP
}

func (j *testJournal) Close() error {
	j.entries = nil
	return nil
}
