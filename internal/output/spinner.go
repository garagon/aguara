package output

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

var spinnerFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

// Spinner displays an animated braille spinner on a writer (typically stderr).
// It is safe for concurrent use — Update may be called from any goroutine.
type Spinner struct {
	mu      sync.Mutex
	w       io.Writer
	message string
	done    chan struct{}
	stopped bool
}

// NewSpinner creates a spinner that writes to w.
func NewSpinner(w io.Writer) *Spinner {
	return &Spinner{w: w}
}

// Start begins the spinner animation with the given message.
func (s *Spinner) Start(message string) {
	s.mu.Lock()
	s.message = message
	s.done = make(chan struct{})
	s.stopped = false
	s.mu.Unlock()

	go s.loop()
}

// Update changes the displayed message while the spinner is running.
func (s *Spinner) Update(message string) {
	s.mu.Lock()
	s.message = message
	s.mu.Unlock()
}

// Stop halts the spinner and clears its line. It is idempotent.
func (s *Spinner) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	s.mu.Unlock()

	close(s.done)

	// Clear the spinner line
	s.mu.Lock()
	fmt.Fprintf(s.w, "\r%s\r", strings.Repeat(" ", len(s.message)+4))
	s.mu.Unlock()
}

func (s *Spinner) loop() {
	tick := time.NewTicker(80 * time.Millisecond)
	defer tick.Stop()

	i := 0
	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.mu.Lock()
			frame := spinnerFrames[i%len(spinnerFrames)]
			msg := s.message
			s.mu.Unlock()

			// Pad with spaces to overwrite any leftover chars from a longer previous message
			line := fmt.Sprintf("\r%c %s", frame, msg)
			padded := fmt.Sprintf("%-80s", line)

			s.mu.Lock()
			fmt.Fprint(s.w, padded)
			s.mu.Unlock()

			i++
		}
	}
}
