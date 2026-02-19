package file

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const maxFallbackBufferBytes = 64 * 1024 * 1024 // 64MB

type FileHandler struct {
	*common.BaseHandler
	apiSession common.APISession
}

func NewFileHandler(cmdExecutor common.CommandExecutor, apiSession common.APISession) *FileHandler {
	return &FileHandler{
		BaseHandler: common.NewBaseHandler(
			common.FileTransfer,
			[]common.CommandType{
				common.Upload,
				common.Download,
			},
			cmdExecutor,
		),
		apiSession: apiSession,
	}
}

func (h *FileHandler) Execute(_ context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	switch cmd {
	case common.Upload.String():
		code, message := h.handleUpload(args)
		h.statFileTransfer(code, download, message, args)
		return code, message, nil
	case common.Download.String():
		return h.handleDownload(args)
	default:
		return 1, "", fmt.Errorf("unknown file command: %s", cmd)
	}
}

func (h *FileHandler) Validate(cmd string, args *common.CommandArgs) error {
	switch cmd {
	case common.Upload.String():
		if args.Username == "" {
			return fmt.Errorf("upload: username is required")
		}
		if len(args.Paths) == 0 {
			return fmt.Errorf("upload: at least one path is required")
		}
		return nil

	case common.Download.String():
		if args.Username == "" {
			return fmt.Errorf("download: username is required")
		}
		// Either Files array or single Path/Content should be provided
		if len(args.Files) == 0 && args.Path == "" && args.Content == "" {
			return fmt.Errorf("download: either Files array or Path/Content is required")
		}
		return nil

	default:
		return fmt.Errorf("unknown file command: %s", cmd)
	}
}

func (h *FileHandler) handleUpload(args *common.CommandArgs) (int, string) {
	log.Debug().
		Str("username", args.Username).
		Str("groupname", args.Groupname).
		Int("pathCount", len(args.Paths)).
		Msg("Uploading files")

	sysProcAttr, homeDirectory, err := h.demoteWithHomeDir(args.Username, args.Groupname)
	if err != nil {
		log.Error().Err(err).Msg("Failed to demote user.")
		return 1, err.Error()
	}

	if len(args.Paths) == 0 {
		return 1, "No paths provided"
	}

	paths, bulk, recursive, err := h.parsePaths(homeDirectory, args.Paths)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse paths")
		return 1, err.Error()
	}

	name, err := h.makeArchive(paths, bulk, recursive, sysProcAttr)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create archive")
		return 1, err.Error()
	}

	fileInfo, err := os.Stat(name)
	if err != nil {
		log.Error().Err(err).Msg("Failed to stat upload source")
		return 1, err.Error()
	}
	contentSize := fileInfo.Size()
	uploadFileName := filepath.Base(name)

	// codeql[go/path-injection]: Intentional - Admin-specified file path for download
	if bulk || recursive {
		defer func() { _ = os.Remove(name) }() // lgtm[go/path-injection]
	}
	thresholdBytes := multipartBufferThresholdBytes()
	useMultipartBuffer := !args.UseBlob && shouldUseMultipartBuffer(contentSize, thresholdBytes)

	var statusCode int
	if args.UseBlob {
		cmd, stdoutPipe, err := startCatCommand(name, sysProcAttr)
		if err != nil {
			log.Error().Err(err).Msg("Failed to start cat command")
			return 1, err.Error()
		}

		_, statusCode, err = h.fileUpload(args.Content, true, stdoutPipe, "", contentSize)
		if err != nil {
			stopCommand(cmd)
			log.Error().Err(err).Msg("Failed to upload file")
			return 1, err.Error()
		}
		if err := cmd.Wait(); err != nil {
			log.Error().Err(err).Msg("Failed to read file content")
			return 1, err.Error()
		}
	} else if useMultipartBuffer {
		requestBody, contentType, err := h.createMultipartBodyFromFile(name, uploadFileName, recursive, sysProcAttr)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create multipart body")
			return 1, err.Error()
		}

		_, statusCode, err = h.fileUpload(args.Content, false, &requestBody, contentType, int64(requestBody.Len()))
		if err != nil {
			log.Error().Err(err).Msg("Failed to upload file")
			return 1, err.Error()
		}
	} else {
		cmd, stdoutPipe, err := startCatCommand(name, sysProcAttr)
		if err != nil {
			log.Error().Err(err).Msg("Failed to start cat command")
			return 1, err.Error()
		}

		requestBody, contentType, contentLength, err := h.createMultipartBodyStream(stdoutPipe, uploadFileName, recursive, contentSize)
		if err != nil {
			stopCommand(cmd)
			log.Error().Err(err).Msg("Failed to create multipart stream")
			return 1, err.Error()
		}

		_, statusCode, err = h.fileUpload(args.Content, false, requestBody, contentType, contentLength)
		if err != nil {
			stopCommand(cmd)
			log.Error().Err(err).Msg("Failed to upload file")
			return 1, err.Error()
		}

		if statusCode == http.StatusLengthRequired {
			closeUploadBody(requestBody)
			stopCommand(cmd)

			fallbackLimitBytes := multipartFallbackBufferLimitBytes(thresholdBytes)
			if !shouldFallbackToBufferedMultipart(contentSize, thresholdBytes) {
				log.Error().
					Int64("contentSize", contentSize).
					Int64("thresholdBytes", thresholdBytes).
					Int64("fallbackLimitBytes", fallbackLimitBytes).
					Msg("Streaming multipart upload rejected with 411 and buffered fallback is disabled for large files")
				return 1, fmt.Sprintf("streaming multipart upload rejected with 411 and buffered fallback is disabled above %d bytes", fallbackLimitBytes)
			}

			log.Warn().
				Int64("contentSize", contentSize).
				Int64("thresholdBytes", thresholdBytes).
				Int64("fallbackLimitBytes", fallbackLimitBytes).
				Msg("Streaming multipart upload rejected with 411. Retrying once with buffered multipart body.")

			requestBodyBuffer, fallbackContentType, fallbackErr := h.createMultipartBodyFromFile(name, uploadFileName, recursive, sysProcAttr)
			if fallbackErr != nil {
				log.Error().Err(fallbackErr).Msg("Failed to create fallback multipart body")
				return 1, fallbackErr.Error()
			}

			_, statusCode, fallbackErr = h.fileUpload(
				args.Content,
				false,
				&requestBodyBuffer,
				fallbackContentType,
				int64(requestBodyBuffer.Len()),
			)
			if fallbackErr != nil {
				log.Error().Err(fallbackErr).Msg("Failed to upload file with fallback buffered multipart body")
				return 1, fallbackErr.Error()
			}
		} else {
			if err := cmd.Wait(); err != nil {
				log.Error().Err(err).Msg("Failed to read file content")
				return 1, err.Error()
			}
		}
	}

	if statusCode == http.StatusOK {
		return 0, fmt.Sprintf("Successfully uploaded %d file(s).", len(paths))
	}

	return 1, "You do not have permission to read on the directory. or directory does not exist"
}

func (h *FileHandler) handleDownload(args *common.CommandArgs) (int, string, error) {
	log.Debug().
		Str("username", args.Username).
		Str("groupname", args.Groupname).
		Str("path", args.Path).
		Msg("Downloading file")

	var code int
	var message string

	sysProcAttr, err := h.demote(args.Username, args.Groupname)
	if err != nil {
		log.Error().Err(err).Msg("Failed to demote user.")
		return 1, err.Error(), nil
	}

	if len(args.Files) == 0 {
		code, message = h.fileDownload(args, sysProcAttr)
		h.statFileTransfer(code, upload, message, args)
	} else {
		for _, file := range args.Files {
			cmdArgs := &common.CommandArgs{
				Username:       file.Username,
				Groupname:      file.Groupname,
				Type:           file.Type,
				Content:        file.Content,
				Path:           file.Path,
				AllowOverwrite: file.AllowOverwrite,
				AllowUnzip:     file.AllowUnzip,
				URL:            file.URL,
			}
			code, message = h.fileDownload(cmdArgs, sysProcAttr)
			h.statFileTransfer(code, upload, message, cmdArgs)
		}
	}

	if code != 0 {
		return code, message, nil
	}

	return 0, "Successfully downloaded files.", nil
}

func (h *FileHandler) fileDownload(args *common.CommandArgs, sysProcAttr *syscall.SysProcAttr) (int, string) {
	if !args.AllowOverwrite && utils.FileExists(args.Path) {
		return 1, fmt.Sprintf("%s already exists.", args.Path)
	}

	if args.Type == "url" {
		return h.fileDownloadFromURL(args, sysProcAttr)
	}

	content, err := h.getFileData(args)
	if err != nil {
		return 1, err.Error()
	}

	isZip := utils.IsZipFile(content, filepath.Ext(args.Path))
	if err := h.writeDownloadContent(args.Path, bytes.NewReader(content), sysProcAttr); err != nil {
		return 1, err.Error()
	}

	if isZip && args.AllowUnzip {
		if err := h.unzipDownloadedFile(args.Path, sysProcAttr); err != nil {
			return 1, err.Error()
		}
	}

	return 0, fmt.Sprintf("Successfully downloaded %s.", args.Path)
}

func (h *FileHandler) fileDownloadFromURL(args *common.CommandArgs, sysProcAttr *syscall.SysProcAttr) (int, string) {
	contentReader, err := h.openURLStream(args.Content)
	if err != nil {
		return 1, err.Error()
	}
	defer func() { _ = contentReader.Close() }()

	if err := h.writeDownloadContentAtomically(args.Path, contentReader, sysProcAttr); err != nil {
		return 1, err.Error()
	}

	if args.AllowUnzip && utils.IsZipPath(args.Path, filepath.Ext(args.Path)) {
		if err := h.unzipDownloadedFile(args.Path, sysProcAttr); err != nil {
			return 1, err.Error()
		}
	}

	return 0, fmt.Sprintf("Successfully downloaded %s.", args.Path)
}

func (h *FileHandler) writeDownloadContentAtomically(path string, content io.Reader, sysProcAttr *syscall.SysProcAttr) error {
	tempPath := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s.%s.part", filepath.Base(path), uuid.NewString()))
	defer func() { _ = os.Remove(tempPath) }()

	if err := h.writeDownloadContent(tempPath, content, sysProcAttr); err != nil {
		return err
	}

	return h.moveDownloadedFile(tempPath, path, sysProcAttr)
}

func (h *FileHandler) writeDownloadContent(path string, content io.Reader, sysProcAttr *syscall.SysProcAttr) error {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("tee %s > /dev/null", utils.Quote(path)))
	cmd.SysProcAttr = sysProcAttr
	cmd.Stdin = content

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to write file: %s", output)
		return formatCommandError(fmt.Sprintf("failed to write downloaded content to %s", path), err, output)
	}

	return nil
}

func (h *FileHandler) moveDownloadedFile(sourcePath, targetPath string, sysProcAttr *syscall.SysProcAttr) error {
	cmd := exec.Command("sh", "-c", fmt.Sprintf("mv %s %s", utils.Quote(sourcePath), utils.Quote(targetPath)))
	cmd.SysProcAttr = sysProcAttr

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to move downloaded file: %s", output)
		return formatCommandError(fmt.Sprintf("failed to move downloaded content from %s to %s", sourcePath, targetPath), err, output)
	}

	return nil
}

func (h *FileHandler) unzipDownloadedFile(path string, sysProcAttr *syscall.SysProcAttr) error {
	escapePath := utils.Quote(path)
	escapeDirPath := utils.Quote(filepath.Dir(path))
	command := fmt.Sprintf("unzip -n %s -d %s && rm %s", escapePath, escapeDirPath, escapePath)
	cmd := exec.Command("sh", "-c", command)
	cmd.SysProcAttr = sysProcAttr

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to unzip file: %s", output)
		return formatCommandError(fmt.Sprintf("failed to unzip %s", path), err, output)
	}

	return nil
}

func formatCommandError(prefix string, err error, output []byte) error {
	detail := strings.TrimSpace(string(output))
	if detail == "" {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return fmt.Errorf("%s: %w: %s", prefix, err, detail)
}

func (h *FileHandler) demote(username, groupname string) (*syscall.SysProcAttr, error) {
	result, err := utils.Demote(username, groupname, utils.DemoteOptions{ValidateGroup: true})
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, nil
	}
	return result.SysProcAttr, nil
}

func (h *FileHandler) demoteWithHomeDir(username, groupname string) (*syscall.SysProcAttr, string, error) {
	result, err := utils.Demote(username, groupname, utils.DemoteOptions{ValidateGroup: false})
	if err != nil {
		return nil, "", err
	}
	if result == nil {
		return nil, "", nil
	}
	return result.SysProcAttr, result.User.HomeDir, nil
}

func multipartBufferThresholdBytes() int64 {
	thresholdMB := config.GlobalSettings.UploadBufferMB
	if thresholdMB <= 0 {
		thresholdMB = config.DefaultUploadBufferMB
	}
	return int64(thresholdMB) * 1024 * 1024
}

func shouldUseMultipartBuffer(contentSize, thresholdBytes int64) bool {
	return thresholdBytes > 0 && contentSize >= 0 && contentSize <= thresholdBytes
}

func multipartFallbackBufferLimitBytes(thresholdBytes int64) int64 {
	return max(thresholdBytes, maxFallbackBufferBytes)
}

func shouldFallbackToBufferedMultipart(contentSize, thresholdBytes int64) bool {
	return contentSize >= 0 && contentSize <= multipartFallbackBufferLimitBytes(thresholdBytes)
}

func (h *FileHandler) parsePaths(homeDirectory string, pathList []string) ([]string, bool, bool, error) {
	paths := make([]string, len(pathList))
	for i, path := range pathList {
		if strings.HasPrefix(path, "~") {
			path = strings.Replace(path, "~", homeDirectory, 1)
		}

		if !filepath.IsAbs(path) {
			path = filepath.Join(homeDirectory, path)
		}

		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, false, false, err
		}
		paths[i] = absPath
	}

	bulk := len(pathList) > 1
	recursive := false

	// codeql[go/path-injection]: Intentional - Admin-specified file path for upload
	if !bulk {
		fileInfo, err := os.Stat(paths[0]) // lgtm[go/path-injection]
		if err != nil {
			return nil, false, false, err
		}
		recursive = fileInfo.IsDir()
	}

	return paths, bulk, recursive, nil
}

func (h *FileHandler) makeArchive(paths []string, bulk, recursive bool, sysProcAttr *syscall.SysProcAttr) (string, error) {
	path := paths[0]

	if !bulk && !recursive {
		return path, nil
	}

	var cmd *exec.Cmd

	if bulk {
		archiveName := filepath.Join(filepath.Dir(path), uuid.New().String()+".zip")
		basePaths := make([]string, len(paths))
		for i, p := range paths {
			basePaths[i] = filepath.Base(p)
		}

		cmd = exec.Command("zip", "-r", archiveName)
		cmd.Args = append(cmd.Args, basePaths...)
		cmd.Dir = filepath.Dir(path)
		cmd.SysProcAttr = sysProcAttr

		if err := cmd.Run(); err != nil {
			return "", err
		}
		return archiveName, nil
	}

	// recursive single directory
	archiveName := path + ".zip"
	cmd = exec.Command("zip", "-r", archiveName, filepath.Base(path))
	cmd.Dir = filepath.Dir(path)
	cmd.SysProcAttr = sysProcAttr

	if err := cmd.Run(); err != nil {
		return "", err
	}
	return archiveName, nil
}

func startCatCommand(path string, sysProcAttr *syscall.SysProcAttr) (*exec.Cmd, io.ReadCloser, error) {
	cmd := exec.Command("cat", path)
	cmd.SysProcAttr = sysProcAttr

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return cmd, stdoutPipe, nil
}

func stopCommand(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	_ = cmd.Wait()
}

func (h *FileHandler) createMultipartBodyFromFile(path, filePath string, isRecursive bool, sysProcAttr *syscall.SysProcAttr) (bytes.Buffer, string, error) {
	cmd := exec.Command("cat", path)
	cmd.SysProcAttr = sysProcAttr

	output, err := cmd.Output()
	if err != nil {
		return bytes.Buffer{}, "", err
	}

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)

	fileWriter, err := writer.CreateFormFile("content", filePath)
	if err != nil {
		return bytes.Buffer{}, "", err
	}

	if _, err = fileWriter.Write(output); err != nil {
		return bytes.Buffer{}, "", err
	}

	if isRecursive {
		if err = writer.WriteField("name", filePath); err != nil {
			return bytes.Buffer{}, "", err
		}
	}

	_ = writer.Close()

	return body, writer.FormDataContentType(), nil
}

func (h *FileHandler) createMultipartBodyStream(content io.Reader, filePath string, isRecursive bool, contentSize int64) (io.Reader, string, int64, error) {
	pipeReader, pipeWriter := io.Pipe()
	writer := multipart.NewWriter(pipeWriter)
	contentType := writer.FormDataContentType()
	contentLength, err := calculateMultipartContentLength(writer.Boundary(), filePath, isRecursive, contentSize)
	if err != nil {
		_ = pipeReader.Close()
		_ = pipeWriter.Close()
		return nil, "", 0, err
	}

	go func() {
		fileWriter, err := writer.CreateFormFile("content", filePath)
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
			return
		}

		if _, err = io.Copy(fileWriter, content); err != nil {
			_ = pipeWriter.CloseWithError(err)
			return
		}

		if isRecursive {
			if err = writer.WriteField("name", filePath); err != nil {
				_ = pipeWriter.CloseWithError(err)
				return
			}
		}

		if err = writer.Close(); err != nil {
			_ = pipeWriter.CloseWithError(err)
			return
		}

		_ = pipeWriter.Close()
	}()

	return pipeReader, contentType, contentLength, nil
}

func calculateMultipartContentLength(boundary, filePath string, isRecursive bool, contentSize int64) (int64, error) {
	if contentSize < 0 {
		return -1, nil
	}

	var metadata bytes.Buffer
	writer := multipart.NewWriter(&metadata)
	if err := writer.SetBoundary(boundary); err != nil {
		return 0, err
	}

	if _, err := writer.CreateFormFile("content", filePath); err != nil {
		return 0, err
	}

	if isRecursive {
		if err := writer.WriteField("name", filePath); err != nil {
			return 0, err
		}
	}

	if err := writer.Close(); err != nil {
		return 0, err
	}

	return int64(metadata.Len()) + contentSize, nil
}

// fileUpload uploads the file to the server
func (h *FileHandler) fileUpload(uploadURL string, useBlob bool, body io.Reader, contentType string, contentLength int64) ([]byte, int, error) {
	if useBlob {
		responseBody, statusCode, err := utils.Put(uploadURL, body, contentLength, 0)
		if err != nil {
			closeUploadBody(body)
		}
		return responseBody, statusCode, err
	}

	if h.apiSession == nil {
		closeUploadBody(body)
		return nil, 0, errors.New("API session not available")
	}

	responseBody, statusCode, err := h.apiSession.MultipartRequest(uploadURL, body, contentType, contentLength, time.Duration(fileUploadTimeout)*time.Second)
	if err != nil {
		closeUploadBody(body)
	}
	return responseBody, statusCode, err
}

func closeUploadBody(body io.Reader) {
	if closer, ok := body.(io.Closer); ok {
		_ = closer.Close()
	}
}

// getFileData fetches file content from URL, text, or base64
func (h *FileHandler) getFileData(args *common.CommandArgs) ([]byte, error) {
	switch args.Type {
	case "url":
		return h.fetchFromURL(args.Content)
	case "text":
		return []byte(args.Content), nil
	case "base64":
		content, err := base64.StdEncoding.DecodeString(args.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 content: %w", err)
		}
		return content, nil
	default:
		return nil, fmt.Errorf("unknown file type: %s", args.Type)
	}
}

func (h *FileHandler) openURLStream(contentURL string) (io.ReadCloser, error) {
	parsedRequestURL, err := url.Parse(contentURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL %q: %w", contentURL, err)
	}

	req, err := http.NewRequest(http.MethodGet, parsedRequestURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	parsedServerURL, err := url.Parse(config.GlobalSettings.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse url: %w", err)
	}

	if parsedRequestURL.Host == parsedServerURL.Host && parsedRequestURL.Scheme == parsedServerURL.Scheme {
		req.Header.Set("Authorization", fmt.Sprintf(`id="%s", key="%s"`,
			config.GlobalSettings.ID, config.GlobalSettings.Key))
	}

	// codeql[go/request-forgery]: Intentional - Admin-specified URL for file content
	client := utils.NewHTTPClient()
	resp, err := client.Do(req) // lgtm[go/request-forgery]
	if err != nil {
		return nil, fmt.Errorf("failed to open URL stream: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		log.Error().Msgf("Failed to download content from URL: %d %s", resp.StatusCode, parsedRequestURL)
		_ = resp.Body.Close()
		return nil, errors.New("downloading content failed")
	}

	return resp.Body, nil
}

// fetchFromURL downloads content from a URL
func (h *FileHandler) fetchFromURL(contentURL string) ([]byte, error) {
	contentStream, err := h.openURLStream(contentURL)
	if err != nil {
		return nil, err
	}
	defer func() { _ = contentStream.Close() }()

	content, err := io.ReadAll(contentStream)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return content, nil
}

// statFileTransfer reports the file transfer status
func (h *FileHandler) statFileTransfer(code int, transferType transferType, message string, args *common.CommandArgs) {
	if scheduler.Rqueue == nil {
		log.Warn().Msg("Request queue not initialized, skipping stat")
		return
	}

	statURL := fmt.Sprint(args.URL + "stat/")
	isSuccess := code == 0

	payload := &commandStat{
		Success: isSuccess,
		Message: message,
		Type:    transferType,
	}
	scheduler.Rqueue.Post(statURL, payload, 10, time.Time{})
}
