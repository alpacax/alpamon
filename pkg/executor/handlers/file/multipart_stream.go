package file

import (
	"bufio"
	"fmt"
	"io"
	"mime/multipart"
	"sync"
)

const multipartCopyBufSize = 64 << 10 // 64 KiB — goroutine-side copy buffer (pool-reused)
const multipartPipeBufSize = 4 << 20  // 4 MiB — bufio flush granularity; each Flush() → one pipe.Write(4MiB)
const multipartReadBufSize = 4 << 20  // 4 MiB — WriteTo read buffer; matches pipe flush so each Read returns 4MiB

const (
	multipartFieldContent = "content"
	multipartFieldName    = "name"
)

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
// producer goroutine owns src.Close() and propagates a non-nil close error
// (e.g., a non-zero `cat` exit from cmdReadCloser) to the reader via
// pw.CloseWithError, so demoted-read failures surface as upload errors
// instead of silent empty/truncated payloads.
//
// hint is the source size in bytes. Pass -1 when unknown. Sources smaller
// than multipartPipeBufSize (4 MiB) skip the bufio + 4 MiB pool buffer and
// use Go's default 32 KiB copy buffer, since payloads that fit in one flush
// don't benefit from the larger pool buffer.
func buildMultipartStream(src io.ReadCloser, fileName string, isRecursive bool, hint int64) (io.ReadCloser, string, error) {
	if hint >= 0 && hint < multipartPipeBufSize {
		return buildMultipartStreamSmall(src, fileName, isRecursive)
	}
	return buildMultipartStreamLarge(src, fileName, isRecursive)
}

// buildMultipartStreamSmall handles sources smaller than multipartPipeBufSize
// (4 MiB) using Go's default 32 KiB copy buffer and no pool allocation —
// avoids 4 MiB over-provisioning for payloads that fit in one flush.
func buildMultipartStreamSmall(src io.ReadCloser, fileName string, isRecursive bool) (io.ReadCloser, string, error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	contentType := mw.FormDataContentType()

	go func() {
		var pipeErr error

		// LIFO defer order: panic-recover → src.Close (latches close err) →
		// pipe-close (uses accumulated pipeErr).
		defer func() {
			if pipeErr != nil {
				_ = pw.CloseWithError(pipeErr)
			} else {
				_ = pw.Close()
			}
		}()
		defer func() {
			if cerr := src.Close(); cerr != nil && pipeErr == nil {
				pipeErr = cerr
			}
		}()
		defer func() {
			if rec := recover(); rec != nil {
				pipeErr = fmt.Errorf("multipart panic: %v", rec)
			}
		}()

		failPipe := func(err error) bool {
			if err != nil && pipeErr == nil {
				pipeErr = err
			}
			return err != nil
		}

		fw, err := mw.CreateFormFile(multipartFieldContent, fileName)
		if failPipe(err) {
			return
		}
		if failPipe(func() error { _, err := io.Copy(fw, src); return err }()) {
			return
		}
		if isRecursive {
			if failPipe(mw.WriteField(multipartFieldName, fileName)) {
				return
			}
		}
		if failPipe(mw.Close()) {
			return
		}
	}()

	return pr, contentType, nil
}

// buildMultipartStreamLarge handles sources >= multipartPipeBufSize (4 MiB)
// or of unknown size, using pool-reused 4 MiB buffers and multipartReader
// for efficient WriteTo.
func buildMultipartStreamLarge(src io.ReadCloser, fileName string, isRecursive bool) (io.ReadCloser, string, error) {
	pr, pw := io.Pipe()
	bufW := bufio.NewWriterSize(pw, multipartPipeBufSize)
	mw := multipart.NewWriter(bufW)
	contentType := mw.FormDataContentType()

	go func() {
		bufPtr := multipartCopyPool.Get().(*[]byte)
		var pipeErr error

		// LIFO defer order: panic-recover → src.Close (latches close err) →
		// pool.Put → pipe-close. Body panics surface via recover; src.Close
		// errors surface only if no earlier failure already set pipeErr.
		defer func() {
			if pipeErr != nil {
				_ = pw.CloseWithError(pipeErr)
			} else {
				_ = pw.Close()
			}
		}()
		defer multipartCopyPool.Put(bufPtr)
		defer func() {
			if cerr := src.Close(); cerr != nil && pipeErr == nil {
				pipeErr = cerr
			}
		}()
		defer func() {
			if rec := recover(); rec != nil {
				pipeErr = fmt.Errorf("multipart panic: %v", rec)
			}
		}()

		failPipe := func(err error) bool {
			if err != nil && pipeErr == nil {
				pipeErr = err
			}
			return err != nil
		}

		fw, err := mw.CreateFormFile(multipartFieldContent, fileName)
		if failPipe(err) {
			return
		}
		_, err = io.CopyBuffer(fw, src, *bufPtr)
		if failPipe(err) {
			return
		}
		if isRecursive {
			if failPipe(mw.WriteField(multipartFieldName, fileName)) {
				return
			}
		}
		if failPipe(mw.Close()) {
			return
		}
		if failPipe(bufW.Flush()) {
			return
		}
	}()

	return multipartReader{pr}, contentType, nil
}
