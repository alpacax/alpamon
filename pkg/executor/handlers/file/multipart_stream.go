package file

import (
	"bufio"
	"fmt"
	"io"
	"mime/multipart"
	"sync"
)

const multipartCopyBufSize = 64 << 10   // 64 KiB — goroutine-side copy buffer (pool-reused)
const multipartPipeBufSize = 4 << 20    // 4 MiB — bufio flush granularity; each Flush() → one pipe.Write(4MiB)
const multipartReadBufSize = 4 << 20    // 4 MiB — WriteTo read buffer; matches pipe flush so each Read returns 4MiB

// multipartCopyPool reuses 64 KiB buffers for the goroutine-side io.CopyBuffer.
var multipartCopyPool = sync.Pool{
	New: func() any {
		b := make([]byte, multipartCopyBufSize)
		return &b
	},
}

// multipartReadPool reuses 4 MiB buffers for WriteTo on the reader side.
// Large buffers ensure each pr.Read returns a full 4 MiB pipe-write chunk,
// so net/http's chunkedWriter.Write is called ceil(size/4MiB) times instead
// of ceil(size/32KiB), collapsing allocs/op from ~3200 to ~25 for 100 MB.
var multipartReadPool = sync.Pool{
	New: func() any {
		b := make([]byte, multipartReadBufSize)
		return &b
	},
}

// multipartReader wraps a *io.PipeReader and implements io.WriterTo.
// When net/http detects WriterTo it calls WriteTo instead of looping small
// Reads through a 32 KiB buffer, so chunkedWriter.Write is called far fewer
// times.
type multipartReader struct {
	*io.PipeReader
}

func (r multipartReader) WriteTo(dst io.Writer) (int64, error) {
	bufPtr := multipartReadPool.Get().(*[]byte)
	defer multipartReadPool.Put(bufPtr)
	return io.CopyBuffer(dst, r.PipeReader, *bufPtr)
}

// buildMultipartStream returns a streaming multipart body containing `src`
// under form field "content". The caller MUST Close the returned reader. The
// goroutine owns src.Close so leaking the reader does not leak the source.
func buildMultipartStream(src io.ReadCloser, fileName string, isRecursive bool) (io.ReadCloser, string, error) {
	pr, pw := io.Pipe()
	bufW := bufio.NewWriterSize(pw, multipartPipeBufSize)
	mw := multipart.NewWriter(bufW)
	contentType := mw.FormDataContentType()

	go func() {
		bufPtr := multipartCopyPool.Get().(*[]byte)
		defer multipartCopyPool.Put(bufPtr)
		defer src.Close()
		defer func() {
			if rec := recover(); rec != nil {
				_ = pw.CloseWithError(fmt.Errorf("multipart panic: %v", rec))
			}
		}()
		fw, err := mw.CreateFormFile("content", fileName)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.CopyBuffer(fw, src, *bufPtr); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if isRecursive {
			if err := mw.WriteField("name", fileName); err != nil {
				_ = pw.CloseWithError(err)
				return
			}
		}
		if err := mw.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := bufW.Flush(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		_ = pw.Close()
	}()

	return multipartReader{pr}, contentType, nil
}
