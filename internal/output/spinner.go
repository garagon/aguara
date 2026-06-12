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
	width   int
	message string
	done    chan struct{}
	stopped bool
}

// NewSpinner creates a spinner that writes to w. Frames are padded to
// the terminal width (capped at 80 columns) so a narrower terminal
// does not wrap the spinner line into a new row on every tick.
func NewSpinner(w io.Writer) *Spinner {
	width := 80
	if detected := DetectWidth(w); detected > 0 && detected < width {
		width = detected
	}
	return &Spinner{w: w, width: width}
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

	// Clear the spinner line. Frames pad to s.width, so clearing the
	// full width covers any message length.
	s.mu.Lock()
	fmt.Fprintf(s.w, "\r%s\r", strings.Repeat(" ", s.width-1))
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
			width := s.width
			s.mu.Unlock()

			// Truncate to the terminal width, then pad with spaces to
			// overwrite any leftover chars from a longer previous message.
			visible := fmt.Sprintf("%c %s", frame, msg)
			if runes := []rune(visible); len(runes) > width-1 {
				visible = string(runes[:width-1])
			}
			padded := fmt.Sprintf("\r%-*s", width-1, visible)

			s.mu.Lock()
			// A Stop racing this tick may have already cleared the
			// line; writing one more frame would leave it on screen.
			if !s.stopped {
				fmt.Fprint(s.w, padded)
			}
			s.mu.Unlock()

			i++
		}
	}
}
