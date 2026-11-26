package client

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
)

// DuEntry is the size of a directory tree.
type DuEntry struct {
	Path  string // slash separated, relative to the share; "" is the root
	Bytes int64  // apparent size (end of file) of every file below, summed
}

// DuOptions configure Du.
type DuOptions struct {
	// Jobs is how many directories are listed at once (default 8). One session
	// multiplexes them; this is a bound on requests in flight, not threads.
	Jobs int
	// Visit is called once per directory, children before parents, never
	// concurrently. nil means no call.
	Visit func(DuEntry)
	// OnError is called for a directory that cannot be listed; the walk goes on
	// and the directory counts as empty. nil ignores them.
	OnError func(path string, err error)
}

// ErrTooDeep is returned when a walk goes deeper than Limits.MaxDepth (a
// directory loop through reparse points would otherwise never end).
var ErrTooDeep = errors.New("directory tree deeper than the limit allows")

// Du sums the size of everything under root (a directory or a file). Symbolic
// links are counted by their own size and never followed. The walk is bounded:
// Limits.MaxWalkNodes entries and Limits.MaxDepth levels, whatever the server
// says; hitting either is an error (ErrTooMany, ErrTooDeep) and the total is
// not to be trusted.
func (sh *Share) Du(ctx context.Context, root string, o DuOptions) (int64, error) {
	jobs := o.Jobs
	if jobs <= 0 {
		jobs = 8
	}
	st, err := sh.sh.WithContext(ctx).Stat(root)
	if err != nil {
		return 0, err
	}
	if !st.IsDir() {
		n := max(st.Size(), 0)
		if o.Visit != nil {
			o.Visit(DuEntry{root, n})
		}
		return n, nil
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	w := &walker{sh: sh.WithContext(ctx), o: o, sem: make(chan struct{}, jobs), cancel: cancel}
	total := w.dir(ctx, root, 0)
	if w.fatal != nil {
		return total, w.fatal
	}
	return total, ctx.Err()
}

type walker struct {
	sh     *Share
	o      DuOptions
	sem    chan struct{}
	cancel context.CancelFunc
	nodes  atomic.Int64
	vis    sync.Mutex
	once   sync.Once
	fatal  error
}

func (w *walker) fail(err error) {
	w.once.Do(func() { w.fatal = err; w.cancel() })
}

func addSat(a, b int64) int64 {
	if b > 0 && a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

func (w *walker) dir(ctx context.Context, path string, depth int) int64 {
	if depth > w.sh.limits.MaxDepth {
		w.fail(fmt.Errorf("%s: %w (%d)", path, ErrTooDeep, w.sh.limits.MaxDepth))
		return 0
	}
	w.sem <- struct{}{}
	ents, err := w.sh.ReadDir(path)
	<-w.sem
	if err != nil {
		if errors.Is(err, ErrTooMany) {
			w.fail(err)
		} else if w.o.OnError != nil && ctx.Err() == nil {
			w.vis.Lock()
			w.o.OnError(path, err)
			w.vis.Unlock()
		}
	}
	if w.nodes.Add(int64(len(ents))) > w.sh.limits.MaxWalkNodes {
		w.fail(fmt.Errorf("%s: %w (%d entries)", path, ErrTooMany, w.sh.limits.MaxWalkNodes))
		return 0
	}
	var total int64
	var subs []string
	for _, e := range ents {
		if e.Dir && !e.Symlink {
			subs = append(subs, join(path, e.Name))
			continue
		}
		total = addSat(total, e.Size)
	}
	sums := make([]int64, len(subs))
	var wg sync.WaitGroup
	for i, s := range subs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sums[i] = w.dir(ctx, s, depth+1)
		}()
	}
	wg.Wait()
	for _, s := range sums {
		total = addSat(total, s)
	}
	if w.o.Visit != nil && ctx.Err() == nil {
		w.vis.Lock()
		w.o.Visit(DuEntry{path, total})
		w.vis.Unlock()
	}
	return total
}

func join(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}
