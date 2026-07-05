package ckalkan

import (
	"sync"
	"testing"
	"time"

	"github.com/skarm/kalkan/ckalkan/internal/kalkancrypt"
)

func TestSerializesConcurrentCalls(t *testing.T) {
	ctx := &fakeNativeContext{}
	var mu sync.Mutex
	var active int
	var maxActive int
	ctx.hashDataFunc = func(string, int, []byte, int) (kalkancrypt.BufferResult, error) {
		mu.Lock()
		active++
		if active > maxActive {
			maxActive = active
		}
		mu.Unlock()

		time.Sleep(time.Millisecond)

		mu.Lock()
		active--
		mu.Unlock()
		return kalkancrypt.BufferResult{Code: uint64(ErrorOK), Data: []byte("ok"), OutLen: 2}, nil
	}

	cli := &Client{ctx: ctx, config: defaultConfig()}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cli.HashData(SHA256, 0, []byte("abc")); err != nil {
				t.Errorf("HashData failed: %v", err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	got := maxActive
	mu.Unlock()
	if got != 1 {
		t.Fatalf("max concurrent backend calls = %d, want 1", got)
	}
}
