package agent

import (
	"testing"
	"time"
)

// BenchmarkContextManager_NewContext measures context creation performance
func BenchmarkContextManager_NewContext(b *testing.B) {
	cm := NewContextManager()
	defer cm.Shutdown()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, cancel := cm.NewContext(0)
		cancel()
	}
}

// BenchmarkContextManager_NewContextWithTimeout measures context creation with timeout
func BenchmarkContextManager_NewContextWithTimeout(b *testing.B) {
	cm := NewContextManager()
	defer cm.Shutdown()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, cancel := cm.NewContext(30 * time.Second)
		cancel()
	}
}

// BenchmarkContextManager_ConcurrentNewContext measures concurrent context creation
func BenchmarkContextManager_ConcurrentNewContext(b *testing.B) {
	cm := NewContextManager()
	defer cm.Shutdown()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, cancel := cm.NewContext(0)
			cancel()
		}
	})
}

// BenchmarkContextManager_NewContextWithDeadline measures deadline context creation
func BenchmarkContextManager_NewContextWithDeadline(b *testing.B) {
	cm := NewContextManager()
	defer cm.Shutdown()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		deadline := time.Now().Add(30 * time.Second)
		_, cancel := cm.NewContextWithDeadline(deadline)
		cancel()
	}
}
