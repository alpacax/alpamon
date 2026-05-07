package file

import (
	"fmt"
	"io"
	"mime/multipart"
)

// buildMultipartStream returns a streaming multipart body containing `src`
// under form field "content". The caller MUST Close the returned reader. The
// goroutine owns src.Close so leaking the reader does not leak the source.
func buildMultipartStream(src io.ReadCloser, fileName string, isRecursive bool) (io.ReadCloser, string, error) {
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	contentType := mw.FormDataContentType()

	go func() {
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
		if _, err := io.Copy(fw, src); err != nil {
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
		_ = pw.Close()
	}()

	return pr, contentType, nil
}
