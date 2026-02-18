// Package state provides a persistent JSON store for tracking file content
// hashes across scan runs. This enables rug-pull detection by comparing
// current tool descriptions against previously observed versions.
package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Entry represents a stored hash for a single file or description.
type Entry struct {
	Hash      string `json:"hash"`
	UpdatedAt string `json:"updated_at"`
}

// Store persists content hashes to a JSON file on disk.
type Store struct {
	mu      sync.RWMutex
	Entries map[string]Entry `json:"entries"`
	path    string
}

// New creates a new Store backed by the given file path.
func New(path string) *Store {
	return &Store{
		Entries: make(map[string]Entry),
		path:    path,
	}
}

// DefaultPath returns the default state file path (~/.aguara/state.json).
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".aguara/state.json"
	}
	return filepath.Join(home, ".aguara", "state.json")
}

// Load reads the state file from disk. If the file doesn't exist,
// the store starts empty (no error).
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return json.Unmarshal(data, s)
}

// Save writes the current state to disk, creating parent directories if needed.
func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.path, data, 0o644)
}

// Get returns the entry for the given key and whether it exists.
func (s *Store) Get(key string) (Entry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.Entries[key]
	return e, ok
}

// Set stores a hash for the given key with the current timestamp.
func (s *Store) Set(key, hash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Entries[key] = Entry{
		Hash:      hash,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}
}

// Path returns the file path of this store.
func (s *Store) Path() string {
	return s.path
}
