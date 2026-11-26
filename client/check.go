package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// StepResult is the outcome of one probe step.
type StepResult struct {
	Step     Step
	OK       bool
	Skipped  bool // an earlier step failed
	Err      error
	Duration time.Duration
}

// Report is the outcome of Check.
type Report struct {
	Steps []StepResult
}

// Failed returns the first failing step, or "" when none failed.
func (r Report) Failed() (Step, error) {
	for _, s := range r.Steps {
		if !s.OK && !s.Skipped {
			return s.Step, s.Err
		}
	}
	return "", nil
}

// Verdict is the one stated line: what worked, or which step failed and why.
func (r Report) Verdict() string {
	if st, err := r.Failed(); st != "" {
		return fmt.Sprintf("FAIL at %s: %v", st, err)
	}
	return "OK: connect, auth, tree connect, read and write all succeeded"
}

// probeSize is the size of the file the write probe creates.
const probeSize = 4096

// Check connects to t, authenticates, tree-connects, then probes the share:
// a read probe (list and stat the directory) and a write probe (create a file
// of random bytes, read it back and compare, delete it). Steps after a failure
// are reported skipped. The write probe's file is removed again on every path
// out of it that can still reach the server.
func Check(ctx context.Context, t Target, o Options) Report {
	var r Report
	fail := false
	run := func(step Step, f func() error) {
		if fail {
			r.Steps = append(r.Steps, StepResult{Step: step, Skipped: true})
			return
		}
		start := time.Now()
		err := f()
		var se *StepError
		if errors.As(err, &se) {
			step, err = se.Step, se.Err
		}
		res := StepResult{Step: step, OK: err == nil, Err: err, Duration: time.Since(start)}
		r.Steps = append(r.Steps, res)
		fail = err != nil
	}
	var sess *Session
	var share *Share
	// Dial reports connect and auth as one call; split its result in two rows.
	start := time.Now()
	s, err := Dial(ctx, t, o)
	d := time.Since(start)
	var se *StepError
	switch {
	case err == nil:
		sess = s
		r.Steps = append(r.Steps, StepResult{Step: StepConnect, OK: true, Duration: d}, StepResult{Step: StepAuth, OK: true})
	case errors.As(err, &se) && se.Step == StepAuth:
		r.Steps = append(r.Steps, StepResult{Step: StepConnect, OK: true, Duration: d}, StepResult{Step: StepAuth, Err: se.Err})
		fail = true
	default:
		r.Steps = append(r.Steps, StepResult{Step: StepConnect, Err: err, Duration: d}, StepResult{Step: StepAuth, Skipped: true})
		fail = true
	}
	if sess != nil {
		defer sess.Close()
	}
	run(StepTree, func() error {
		sh, err := sess.Mount(t.Share)
		share = sh
		return err
	})
	if share != nil {
		defer share.Close()
	}
	run(StepRead, func() error {
		if _, err := share.sh.Stat(t.Path); err != nil {
			return err
		}
		if _, err := share.ReadDir(t.Path); err != nil && !errors.Is(err, ErrTooMany) {
			return err
		}
		return nil
	})
	name := t.Path
	var probe string
	var probeData []byte
	run(StepWriteCreate, func() error {
		var b [8]byte
		rand.Read(b[:]) // crypto/rand.Read does not return an error since Go 1.24
		probe = join(name, ".smbc-check-"+hex.EncodeToString(b[:]))
		data := make([]byte, probeSize)
		rand.Read(data)
		if err := share.sh.WriteFile(probe, data, 0o600); err != nil {
			return err
		}
		probeData = data
		return nil
	})
	run(StepWriteVerify, func() error {
		f, err := share.sh.Open(probe)
		if err != nil {
			return err
		}
		defer f.Close()
		got, err := io.ReadAll(io.LimitReader(f, share.limits.MaxProbeRead))
		if err != nil {
			return err
		}
		if !bytes.Equal(got, probeData) {
			return fmt.Errorf("read back %d bytes that differ from the %d written", len(got), len(probeData))
		}
		return nil
	})
	// The delete runs even when the verify failed, so a probe file is not left
	// behind; it is reported skipped only when nothing was ever created.
	if probe != "" && share != nil {
		fail = false
	}
	run(StepWriteDelete, func() error {
		if err := share.sh.Remove(probe); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	})
	return r
}
