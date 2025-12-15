package tunnel

import (
	"io"
	"sync"
)

const copyBufferSize = 32 * 1024 // 32KB

var copyBufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, copyBufferSize)
	},
}

// CopyBuffered performs io.CopyBuffer using pooled buffers.
// This reduces memory allocations and GC pressure.
func CopyBuffered(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := copyBufferPool.Get().([]byte)
	defer copyBufferPool.Put(buf)
	return io.CopyBuffer(dst, src, buf)
}
