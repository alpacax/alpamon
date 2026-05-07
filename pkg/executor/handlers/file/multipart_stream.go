package file

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"sync"
)

const (
	multipartBufferedThreshold = 64 << 10 // bytes.Buffer beats streaming up to ~64 KiB — streaming's goroutine + pipe overhead dominates KB-scale bodies; single-iter buffered peak (~2× hint) stays under 128 KiB at this threshold
	multipartCopyBufSize       = 64 << 10
	multipartPipeBufSize       = 4 << 20 // bufio flush granularity; one Flush() → one 4 MiB pipe.Write
	multipartReadBufSize       = 4 << 20 // matches pipe flush so each pr.Read returns a full 4 MiB chunk
)

const (
	multipartFieldContent = "content"
	multipartFieldName    = "name"
)

var multipartCopyPool = sync.Pool{
	New: func() any {
		b := make([]byte, multipartCopyBufSize)
		return &b
	},
}

// 4 MiB reads collapse net/http's chunkedWriter.Write count from ceil(size/32KiB) to ceil(size/4MiB).
var multipartReadPool = sync.Pool{
	New: func() any {
		b := make([]byte, multipartReadBufSize)
		return &b
	},
}

// Without pooling, each concurrent upload would allocate a fresh 4 MiB bufio buffer.
var multipartPipeWriterPool = sync.Pool{
	New: func() any {
		return bufio.NewWriterSize(io.Discard, multipartPipeBufSize)
	},
}

// multipartReader exposes WriterTo so net/http's chunkedWriter sees 4 MiB
// chunks instead of looping reads through its 32 KiB internal buffer.
type multipartReader struct {
	*io.PipeReader
}

func (r multipartReader) WriteTo(dst io.Writer) (int64, error) {
	bufPtr := multipartReadPool.Get().(*[]byte)
	defer multipartReadPool.Put(bufPtr)
	return io.CopyBuffer(dst, r.PipeReader, *bufPtr)
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// multipartEnvelopeSize replays the writer operations on a counter to measure
// the envelope (boundary frames + headers + closer) excluding the body.
// total_wire = envelope + bodyN, since mime/multipart's output is determined
// by (boundary, fileName, isRecursive) alone — independent of body bytes.
func multipartEnvelopeSize(boundary, fileName string, isRecursive bool) (int64, error) {
	var c countingWriter
	mw := multipart.NewWriter(&c)
	if err := mw.SetBoundary(boundary); err != nil {
		return 0, err
	}
	if _, err := mw.CreateFormFile(multipartFieldContent, fileName); err != nil {
		return 0, err
	}
	if isRecursive {
		if err := mw.WriteField(multipartFieldName, fileName); err != nil {
			return 0, err
		}
	}
	if err := mw.Close(); err != nil {
		return 0, err
	}
	return c.n, nil
}

// buildMultipartStream returns a multipart body and the Content-Length to send
// (or -1 for chunked TE). Three paths, picked by hint:
//
//   - hint ≤ 64 KiB: bytes.Buffer (synchronous, identity TE, no goroutine).
//   - hint < 4 MiB:  io.Pipe small (identity TE via precomputed envelope).
//   - hint ≥ 4 MiB or unknown: io.Pipe large (chunked TE; finite ContentLength
//     would make net/http wrap body in io.LimitReader and strip multipartReader's
//     WriterTo, forcing 32 KiB reads and crushing throughput).
//
// Streaming paths' producer goroutine owns src.Close and surfaces close errors
// (e.g., non-zero `cat` exit from cmdReadCloser) via pw.CloseWithError so a
// failed demoted read doesn't silently complete as an empty upload.
func buildMultipartStream(src io.ReadCloser, fileName string, isRecursive bool, hint int64) (io.ReadCloser, string, int64, error) {
	if hint >= 0 && hint <= multipartBufferedThreshold {
		return buildMultipartBuffered(src, fileName, isRecursive)
	}
	if hint >= 0 && hint < multipartPipeBufSize {
		return buildMultipartStreamSmall(src, fileName, isRecursive, hint)
	}
	return buildMultipartStreamLarge(src, fileName, isRecursive)
}

func buildMultipartBuffered(src io.ReadCloser, fileName string, isRecursive bool) (io.ReadCloser, string, int64, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	contentType := mw.FormDataContentType()

	fw, err := mw.CreateFormFile(multipartFieldContent, fileName)
	if err != nil {
		_ = src.Close()
		return nil, "", 0, err
	}
	if _, err := io.Copy(fw, src); err != nil {
		_ = src.Close()
		return nil, "", 0, err
	}
	if err := src.Close(); err != nil {
		return nil, "", 0, err
	}
	if isRecursive {
		if err := mw.WriteField(multipartFieldName, fileName); err != nil {
			return nil, "", 0, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, "", 0, err
	}
	return io.NopCloser(&buf), contentType, int64(buf.Len()), nil
}

func buildMultipartStreamSmall(src io.ReadCloser, fileName string, isRecursive bool, hint int64) (io.ReadCloser, string, int64, error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	contentType := mw.FormDataContentType()

	contentLength := int64(-1)
	if hint >= 0 {
		env, err := multipartEnvelopeSize(mw.Boundary(), fileName, isRecursive)
		if err != nil {
			_ = src.Close()
			_ = pw.Close()
			return nil, "", 0, err
		}
		contentLength = env + hint
	}

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

	return pr, contentType, contentLength, nil
}

// buildMultipartStreamLarge pools all three multi-MiB allocations
// (multipartPipeWriterPool, multipartCopyPool, multipartReadPool) so RSS
// stays flat across concurrent uploads.
func buildMultipartStreamLarge(src io.ReadCloser, fileName string, isRecursive bool) (io.ReadCloser, string, int64, error) {
	pr, pw := io.Pipe()
	bufW := multipartPipeWriterPool.Get().(*bufio.Writer)
	bufW.Reset(pw)
	mw := multipart.NewWriter(bufW)
	contentType := mw.FormDataContentType()

	go func() {
		bufPtr := multipartCopyPool.Get().(*[]byte)
		var pipeErr error

		// LIFO defer order: panic-recover → src.Close (latches close err) →
		// pool puts → pipe-close. Body panics surface via recover; src.Close
		// errors surface only if no earlier failure already set pipeErr.
		// bufW is reset to io.Discard before being returned to the pool so it
		// does not retain a reference to pw after we hand it back.
		defer func() {
			if pipeErr != nil {
				_ = pw.CloseWithError(pipeErr)
			} else {
				_ = pw.Close()
			}
		}()
		defer func() {
			bufW.Reset(io.Discard)
			multipartPipeWriterPool.Put(bufW)
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

	return multipartReader{pr}, contentType, -1, nil
}
