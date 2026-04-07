package file

import (
	"bufio"
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

// FileHandler handles file transfer commands
type FileHandler struct {
	*common.BaseHandler
	apiSession common.APISession
}

// NewFileHandler creates a new file handler
func NewFileHandler(cmdExecutor common.CommandExecutor, apiSession common.APISession) *FileHandler {
	h := &FileHandler{
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
	return h
}

// Execute runs the file transfer command
func (h *FileHandler) Execute(ctx context.Context, cmd string, args *common.CommandArgs) (int, string, error) {
	ctx, cancel := common.WithHandlerTimeout(ctx, common.FileTimeout)
	defer cancel()

	var code int
	var message string

	switch cmd {
	case common.Upload.String():
		code, message = h.handleUpload(ctx, args)
		h.statFileTransfer(code, download, message, args)
	case common.Download.String():
		var err error
		code, message, err = h.handleDownload(ctx, args)
		if err != nil {
			if common.IsTimeout(ctx) {
				return common.TimeoutError(common.FileTimeout)
			}
			return code, message, err
		}
	default:
		return 1, "", fmt.Errorf("unknown file command: %s", cmd)
	}

	if common.IsTimeout(ctx) {
		return common.TimeoutError(common.FileTimeout)
	}
	return code, message, nil
}

// Validate checks if the arguments are valid for the command
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

// handleUpload handles the upload command
func (h *FileHandler) handleUpload(ctx context.Context, args *common.CommandArgs) (int, string) {
	log.Debug().
		Str("username", args.Username).
		Str("groupname", args.Groupname).
		Int("pathCount", len(args.Paths)).
		Msg("Uploading files")

	if len(args.Paths) == 0 {
		return 1, "No paths provided"
	}

	sysProcAttr, homeDirectory, err := h.demoteWithHomeDir(args.Username, args.Groupname)
	if err != nil {
		log.Error().Err(err).Msg("Failed to demote user.")
		return 1, err.Error()
	}

	paths, bulk, recursive, err := h.parsePaths(homeDirectory, args.Paths)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse paths")
		return 1, err.Error()
	}

	name, cleanupPath, err := h.makeArchive(ctx, paths, bulk, recursive, sysProcAttr)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create archive")
		return 1, err.Error()
	}

	if cleanupPath != "" {
		defer func() { _ = os.Remove(cleanupPath) }()
	}

	catCmd := exec.CommandContext(ctx, "cat", name)
	catCmd.SysProcAttr = sysProcAttr

	fileStream, err := catCmd.StdoutPipe()
	if err != nil {
		log.Error().Err(err).Msg("Failed to create archive stream")
		return 1, err.Error()
	}

	var catStderr bytes.Buffer
	catCmd.Stderr = &catStderr

	if err := catCmd.Start(); err != nil {
		log.Error().Err(err).Msg("Failed to start archive stream")
		return 1, err.Error()
	}

	requestBody, contentType, waitForBody, err := h.createMultipartBody(fileStream, filepath.Base(name), args.UseBlob, recursive)
	if err != nil {
		log.Error().Err(err).Msg("Failed to make request body")
		return 1, err.Error()
	}

	_, statusCode, err := h.fileUpload(args.Content, args.UseBlob, requestBody, contentType)
	bodyErr := waitForBody()
	catErr := catCmd.Wait()
	if err != nil {
		log.Error().Err(err).Msg("Failed to upload file")
		return 1, err.Error()
	}
	if catErr != nil {
		log.Error().Err(catErr).Str("stderr", catStderr.String()).Msg("Failed to stream file content")
		return 1, catErr.Error()
	}
	if bodyErr != nil {
		log.Error().Err(bodyErr).Msg("Failed to write multipart request body")
		return 1, bodyErr.Error()
	}

	if statusCode == http.StatusOK {
		return 0, fmt.Sprintf("Successfully uploaded %d file(s).", len(paths))
	}

	return 1, "You do not have permission to read on the directory. or directory does not exist"
}

// handleDownload handles the download command
func (h *FileHandler) handleDownload(ctx context.Context, args *common.CommandArgs) (int, string, error) {
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
		code, message = h.fileDownload(ctx, args, sysProcAttr)
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
			code, message = h.fileDownload(ctx, cmdArgs, sysProcAttr)
			h.statFileTransfer(code, upload, message, cmdArgs)
		}
	}

	if code != 0 {
		return code, message, nil
	}

	return 0, "Successfully downloaded files.", nil
}

// fileDownload handles single file download
func (h *FileHandler) fileDownload(ctx context.Context, args *common.CommandArgs, sysProcAttr *syscall.SysProcAttr) (int, string) {
	if !args.AllowOverwrite && utils.FileExists(args.Path) {
		return 1, fmt.Sprintf("%s already exists.", args.Path)
	}

	contentReader, err := h.getFileReader(args)
	if err != nil {
		return 1, err.Error()
	}
	defer func() { _ = contentReader.Close() }()

	cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("tee %s > /dev/null", utils.Quote(args.Path)))
	cmd.SysProcAttr = sysProcAttr
	cmd.Stdin = contentReader
	cmd.Stdout = io.Discard

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		log.Error().Err(err).Str("stderr", stderr.String()).Msg("Failed to write file")
		return 1, "You do not have permission to read on the directory. or directory does not exist"
	}

	if args.AllowUnzip {
		isZip, err := utils.IsZipFilePath(args.Path)
		if err != nil {
			log.Error().Err(err).Msg("Failed to inspect downloaded file")
			return 1, err.Error()
		}

		if isZip {
			if err := h.unzipDownloadedFile(ctx, args.Path, sysProcAttr); err != nil {
				log.Error().Err(err).Msg("Failed to unzip downloaded file")
				return 1, err.Error()
			}
		}
	}

	return 0, fmt.Sprintf("Successfully downloaded %s.", args.Path)
}

// demote demotes privilege to the specified user/group
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

// demoteWithHomeDir demotes privilege and returns home directory
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

// parsePaths parses and validates the path list
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

	isBulk := len(pathList) > 1
	isRecursive := false

	// codeql[go/path-injection]: Intentional - Admin-specified file path for upload
	if !isBulk {
		fileInfo, err := os.Stat(paths[0]) // lgtm[go/path-injection]
		if err != nil {
			return nil, false, false, err
		}
		isRecursive = fileInfo.IsDir()
	}

	return paths, isBulk, isRecursive, nil
}

// makeArchive creates a zip archive from the specified paths.
// It returns the archive file path, a cleanup path (non-empty only for temp archives), and any error.
// cleanupPath is always derived from os.TempDir() and never from user input,
// ensuring os.Remove(cleanupPath) is safe from path-injection.
func (h *FileHandler) makeArchive(ctx context.Context, paths []string, bulk, recursive bool, sysProcAttr *syscall.SysProcAttr) (string, string, error) {
	var archiveName string
	var cleanupPath string
	var cmd *exec.Cmd
	path := paths[0]

	if bulk {
		archiveName = filepath.Join(os.TempDir(), uuid.New().String()+".zip")
		cleanupPath = archiveName
		dirPath := filepath.Dir(path)
		basePaths := make([]string, len(paths))
		for i, p := range paths {
			basePaths[i] = filepath.Base(p)
		}

		cmd = exec.CommandContext(ctx, "zip", "-r", archiveName)
		cmd.SysProcAttr = sysProcAttr
		cmd.Args = append(cmd.Args, basePaths...)
		cmd.Dir = dirPath
	} else {
		if recursive {
			archiveName = filepath.Join(os.TempDir(), uuid.New().String()+".zip")
			cleanupPath = archiveName
			cmd = exec.CommandContext(ctx, "zip", "-r", archiveName, filepath.Base(path))
			cmd.SysProcAttr = sysProcAttr
			cmd.Dir = filepath.Dir(path)
		} else {
			archiveName = path
			// cleanupPath stays ""—single file, no temp archive to clean up
		}
	}

	if bulk || recursive {
		err := cmd.Run()
		if err != nil {
			if cleanupPath != "" {
				_ = os.Remove(cleanupPath)
			}
			return "", "", err
		}
	}

	return archiveName, cleanupPath, nil
}

// createMultipartBody creates a multipart form body for file upload.
func (h *FileHandler) createMultipartBody(fileStream io.Reader, filePath string, useBlob, isRecursive bool) (io.Reader, string, func() error, error) {
	if useBlob {
		return fileStream, "", func() error { return nil }, nil
	}

	pipeReader, pipeWriter := io.Pipe()
	buffered := bufio.NewWriterSize(pipeWriter, 256*1024)
	writer := multipart.NewWriter(buffered)
	done := make(chan error, 1)

	go func() {
		fileWriter, err := writer.CreateFormFile("content", filePath)
		if err == nil {
			_, err = io.Copy(fileWriter, fileStream)
		}
		if err == nil && isRecursive {
			err = writer.WriteField("name", filePath)
		}
		if err != nil {
			_ = pipeWriter.CloseWithError(err)
			done <- err
			return
		}
		if err := writer.Close(); err != nil {
			_ = pipeWriter.CloseWithError(err)
			done <- err
			return
		}
		if err := buffered.Flush(); err != nil {
			_ = pipeWriter.CloseWithError(err)
			done <- err
			return
		}
		if err := pipeWriter.Close(); err != nil {
			done <- err
			return
		}
		done <- nil
	}()

	return pipeReader, writer.FormDataContentType(), func() error {
		return <-done
	}, nil
}

// fileUpload uploads the file to the server
func (h *FileHandler) fileUpload(uploadURL string, useBlob bool, body io.Reader, contentType string) ([]byte, int, error) {
	if useBlob {
		return utils.Put(uploadURL, body, 0)
	}

	if h.apiSession == nil {
		return nil, 0, errors.New("API session not available")
	}

	return h.apiSession.MultipartRequest(uploadURL, body, contentType, time.Duration(fileUploadTimeout)*time.Second)
}

// getFileReader fetches file content from URL, text, or base64 as a stream.
func (h *FileHandler) getFileReader(args *common.CommandArgs) (io.ReadCloser, error) {
	switch args.Type {
	case "url":
		return h.fetchFromURL(args.Content)
	case "text":
		return io.NopCloser(strings.NewReader(args.Content)), nil
	case "base64":
		return io.NopCloser(base64.NewDecoder(base64.StdEncoding, strings.NewReader(args.Content))), nil
	default:
		return nil, fmt.Errorf("unknown file type: %s", args.Type)
	}
}

// fetchFromURL opens a streaming response body for a URL.
func (h *FileHandler) fetchFromURL(contentURL string) (io.ReadCloser, error) {
	parsedRequestURL, err := url.Parse(contentURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL '%s': %w", contentURL, err)
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
		return nil, fmt.Errorf("failed to download content from URL: %w", err)
	}

	if resp.StatusCode/100 != 2 {
		_ = resp.Body.Close()
		log.Error().Msgf("Failed to download content from URL: %d %s", resp.StatusCode, parsedRequestURL)
		return nil, errors.New("downloading content failed")
	}

	return resp.Body, nil
}

func (h *FileHandler) unzipDownloadedFile(ctx context.Context, path string, sysProcAttr *syscall.SysProcAttr) error {
	cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("unzip -n %s -d %s && rm %s",
		utils.Quote(path),
		utils.Quote(filepath.Dir(path)),
		utils.Quote(path)))
	cmd.SysProcAttr = sysProcAttr
	cmd.Stdout = io.Discard

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		log.Error().Err(err).Str("stderr", stderr.String()).Msg("Failed to unzip file")
		return err
	}

	return nil
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
