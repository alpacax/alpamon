package tunnel

import (
	"io"
	"sync"
)

// BufferPool manages reusable byte buffers to reduce GC pressure.
type BufferPool struct {
	pool sync.Pool
	size int
}

// Pre-configured buffer pools for common use cases.
var (
	// CopyBuffer is the default pool for io.Copy operations (32KB).
	CopyBuffer = NewBufferPool(32 * 1024)
	// SmallBuffer is for smaller operations (4KB).
	SmallBuffer = NewBufferPool(4 * 1024)
)

// NewBufferPool creates a new buffer pool with the specified buffer size.
func NewBufferPool(size int) *BufferPool {
	return &BufferPool{
		size: size,
		pool: sync.Pool{
			New: func() interface{} {
				return make([]byte, size)
			},
		},
	}
}

// Get retrieves a buffer from the pool.
func (p *BufferPool) Get() []byte {
	return p.pool.Get().([]byte)
}

// Put returns a buffer to the pool.
// Only buffers with matching capacity are accepted.
func (p *BufferPool) Put(buf []byte) {
	if cap(buf) == p.size {
		p.pool.Put(buf[:p.size])
	}
}

// CopyBuffered performs io.CopyBuffer using pooled buffers.
// This reduces memory allocations and GC pressure.
func CopyBuffered(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := CopyBuffer.Get()
	defer CopyBuffer.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}

// CopyBufferedWithPool performs io.CopyBuffer using a specific pool.
func CopyBufferedWithPool(dst io.Writer, src io.Reader, pool *BufferPool) (written int64, err error) {
	buf := pool.Get()
	defer pool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}
