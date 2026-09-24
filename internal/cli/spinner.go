package cli

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// spinner animates a progress line on a terminal. It is a no-op unless
// enabled, so piped output and verbose logs are never polluted by control
// sequences.
type spinner struct {
	w       io.Writer
	enabled bool

	mu   sync.Mutex
	text string
	stop chan struct{}
	done chan struct{}
}

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸"}

func newSpinner(w io.Writer, enabled bool) *spinner {
	return &spinner{w: w, enabled: enabled}
}

func (s *spinner) Start(text string) {
	if !s.enabled {
		return
	}
	s.mu.Lock()
	s.text = text
	s.mu.Unlock()
	s.stop, s.done = make(chan struct{}), make(chan struct{})
	go func() {
		defer close(s.done)
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			select {
			case <-s.stop:
				return
			case <-t.C:
				s.mu.Lock()
				fmt.Fprintf(s.w, "\r\x1b[K%s %s", spinnerFrames[i%len(spinnerFrames)], s.text)
				s.mu.Unlock()
			}
		}
	}()
}

func (s *spinner) Update(text string) {
	if !s.enabled {
		return
	}
	s.mu.Lock()
	s.text = text
	s.mu.Unlock()
}

func (s *spinner) Stop() {
	if !s.enabled || s.stop == nil {
		return
	}
	close(s.stop)
	<-s.done
	s.stop = nil
	fmt.Fprint(s.w, "\r\x1b[K")
}
