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
	if s.stop != nil {
		// Already running: update text and return without leaking goroutines.
		s.text = text
		s.mu.Unlock()
		return
	}
	s.text = text
	stop, done := make(chan struct{}), make(chan struct{})
	s.stop, s.done = stop, done
	s.mu.Unlock()
	go func() {
		defer close(done)
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			select {
			case <-stop:
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
	if !s.enabled {
		return
	}
	s.mu.Lock()
	stop, done := s.stop, s.done
	s.stop, s.done = nil, nil
	s.mu.Unlock()
	if stop == nil {
		return
	}
	close(stop)
	<-done
	fmt.Fprint(s.w, "\r\x1b[K")
}
