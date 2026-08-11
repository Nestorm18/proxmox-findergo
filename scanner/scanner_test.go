package scanner

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunKindReportsProgress(t *testing.T) {
	ips := []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"}
	var mu sync.Mutex
	progress := make([]int, 0, 3)

	runKind(context.Background(), ips, scanKind{
		timeout: time.Second,
		finder: func(context.Context, string, time.Duration) (string, bool) {
			return "", false
		},
	}, Callbacks{OnProgress: func(scanned, total int) {
		if total != len(ips) {
			t.Errorf("total = %d; want %d", total, len(ips))
		}
		mu.Lock()
		progress = append(progress, scanned)
		mu.Unlock()
	}})

	mu.Lock()
	defer mu.Unlock()
	foundFinal := false
	for _, scanned := range progress {
		if scanned == len(ips) {
			foundFinal = true
		}
	}
	if !foundFinal {
		t.Fatalf("progress updates %v do not contain the final value", progress)
	}
}

func TestRunKindDoesNotLaunchAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var calls atomic.Int64

	results := runKind(ctx, []string{"1", "2", "3"}, scanKind{
		timeout: time.Second,
		finder: func(context.Context, string, time.Duration) (string, bool) {
			calls.Add(1)
			return "", false
		},
	}, Callbacks{})

	if got := calls.Load(); got != 0 {
		t.Fatalf("finder called %d times after cancellation", got)
	}
	if len(results) != 0 {
		t.Fatalf("got %d results after cancellation", len(results))
	}
}
