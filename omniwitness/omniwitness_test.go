package omniwitness_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/transparency-dev/witness/internal/persistence/inmemory"
	"github.com/transparency-dev/witness/omniwitness"
	"golang.org/x/sync/errgroup"
)

func TestMainStartupShutdown(t *testing.T) {
	// Root context for the test
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	p := inmemory.NewPersistence()

	var g errgroup.Group
	g.Go(func() error {
		return omniwitness.Main(ctx, omniwitness.OperatorConfig{}, p, listener, http.DefaultClient)
	})

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Shut it down
	cancel()

	err = g.Wait()
	if err != nil && err != context.Canceled && err != http.ErrServerClosed {
		t.Errorf("Main returned unexpected error: %v", err)
	}
}
