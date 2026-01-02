package pool

import (
	"context"
	"sync"
	"testing"
	"time"
)

// BenchmarkPool_WorkerScaling measures performance with different worker counts
func BenchmarkPool_WorkerScaling(b *testing.B) {
	workerCounts := []int{1, 5, 10, 20, 50}

	for _, workers := range workerCounts {
		b.Run(string(rune('0'+workers/10)+rune('0'+workers%10))+"workers", func(b *testing.B) {
			pool := NewPool(workers, 1000)
			ctx := context.Background()

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = pool.Submit(ctx, func() error {
					return nil
				})
			}
			b.StopTimer()

			_ = pool.Shutdown(5 * time.Second)
		})
	}
}

// BenchmarkPool_QueueThroughput measures queue throughput under load
func BenchmarkPool_QueueThroughput(b *testing.B) {
	pool := NewPool(10, 50000)
	ctx := context.Background()

	var wg sync.WaitGroup

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		err := pool.Submit(ctx, func() error {
			wg.Done()
			return nil
		})
		if err != nil {
			wg.Done() // Decrement if submission failed
		}
	}
	wg.Wait()
	b.StopTimer()

	_ = pool.Shutdown(5 * time.Second)
}

// BenchmarkPool_ConcurrentSubmit measures concurrent submission performance
func BenchmarkPool_ConcurrentSubmit(b *testing.B) {
	pool := NewPool(20, 5000)
	ctx := context.Background()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = pool.Submit(ctx, func() error {
				return nil
			})
		}
	})
	b.StopTimer()

	_ = pool.Shutdown(10 * time.Second)
}

// BenchmarkPool_WithWork measures performance with actual work
func BenchmarkPool_WithWork(b *testing.B) {
	pool := NewPool(10, 50000)
	ctx := context.Background()

	var wg sync.WaitGroup

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		err := pool.Submit(ctx, func() error {
			// Simulate light work
			sum := 0
			for j := 0; j < 100; j++ {
				sum += j
			}
			_ = sum
			wg.Done()
			return nil
		})
		if err != nil {
			wg.Done() // Decrement if submission failed
		}
	}
	wg.Wait()
	b.StopTimer()

	_ = pool.Shutdown(5 * time.Second)
}
