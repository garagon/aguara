package intel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type observedBody struct {
	remaining, read int
	closed          bool
	err             error
}

func (b *observedBody) Read(p []byte) (int, error) {
	if b.err != nil {
		return 0, b.err
	}
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), b.remaining)
	for i := range n {
		p[i] = 'a'
	}
	b.remaining -= n
	b.read += n
	return n, nil
}

func (b *observedBody) Close() error {
	b.closed = true
	return nil
}

type responseTransport struct{ response *http.Response }

func (r responseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return r.response, nil
}

func TestFetchAndImportReadBudget(t *testing.T) {
	const limit = 1024
	// Actual bytes, not the claimed length, control the bound. The transport is
	// in-process; none of these requests can reach the network.
	for _, claimedLength := range []int64{-1, 1, 4096} {
		body := &observedBody{remaining: 4096}
		client := &http.Client{Transport: responseTransport{&http.Response{
			StatusCode: http.StatusOK, Body: body, ContentLength: claimedLength,
		}}}
		imported := false
		importer := func(io.ReaderAt, int64, []string, time.Time) (Snapshot, error) {
			imported = true
			return Snapshot{}, nil
		}
		snap, size, err := fetchAndImport(context.Background(), client, "https://example.invalid/%s", "npm", time.Time{}, importer, limit)
		require.EqualError(t, err, "response 1025 bytes exceeds cap 1024")
		require.Equal(t, Snapshot{}, snap)
		require.Zero(t, size)
		require.False(t, imported)
		require.Equal(t, limit+1, body.read, "must not drain the remaining body")
		require.True(t, body.closed)
	}
}

func TestFetchAndImportReadErrorClosesBody(t *testing.T) {
	sentinel := errors.New("reader failed")
	body := &observedBody{err: sentinel}
	client := &http.Client{Transport: responseTransport{&http.Response{StatusCode: http.StatusOK, Body: body}}}
	imported := false
	importer := func(io.ReaderAt, int64, []string, time.Time) (Snapshot, error) {
		imported = true
		return Snapshot{}, nil
	}
	snap, size, err := fetchAndImport(context.Background(), client, "https://example.invalid/%s", "npm", time.Time{}, importer, 1024)
	require.ErrorIs(t, err, sentinel)
	require.Equal(t, Snapshot{}, snap)
	require.Zero(t, size)
	require.False(t, imported)
	require.True(t, body.closed)
}
