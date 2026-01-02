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

	// codeql[go/path-injection]: Intentional - Admin-specified file path for download
	if bulk || recursive {
		defer func() { _ = os.Remove(name) }() // lgtm[go/path-injection]
	}

	cmd := exec.Command("cat", name)
	cmd.SysProcAttr = sysProcAttr

	output, err := cmd.Output()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to cat file: %s", output)
		return 1, err.Error()
	}

	requestBody, contentType, err := h.createMultipartBody(output, filepath.Base(name), args.UseBlob, recursive)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to make request body")
		return 1, err.Error()
	}

	_, statusCode, err := h.fileUpload(args.Content, args.UseBlob, requestBody, contentType)
	if err != nil {
		log.Error().Err(err).Msg("Failed to upload file")
		return 1, err.Error()
	}

	if statusCode == http.StatusOK {
		return 0, fmt.Sprintf("Successfully uploaded %d file(s).", len(paths))
	}

	return 1, "You do not have permission to read on the directory. or directory does not exist"
}

// handleDownload handles the download command
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

// fileDownload handles single file download
func (h *FileHandler) fileDownload(args *common.CommandArgs, sysProcAttr *syscall.SysProcAttr) (int, string) {
	var cmd *exec.Cmd
	content, err := h.getFileData(args)
	if err != nil {
		return 1, err.Error()
	}

	if !args.AllowOverwrite && utils.FileExists(args.Path) {
		return 1, fmt.Sprintf("%s already exists.", args.Path)
	}

	isZip := utils.IsZipFile(content, filepath.Ext(args.Path))
	if isZip && args.AllowUnzip {
		escapePath := utils.Quote(args.Path)
		escapeDirPath := utils.Quote(filepath.Dir(args.Path))
		command := fmt.Sprintf("tee %s > /dev/null && unzip -n %s -d %s; rm %s",
			escapePath,
			escapePath,
			escapeDirPath,
			escapePath)
		cmd = exec.Command("sh", "-c", command)
	} else {
		cmd = exec.Command("sh", "-c", fmt.Sprintf("tee %s > /dev/null", utils.Quote(args.Path)))
	}

	cmd.SysProcAttr = sysProcAttr
	cmd.Stdin = bytes.NewReader(content)

	output, err := cmd.Output()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to write file: %s", output)
		return 1, "You do not have permission to read on the directory. or directory does not exist"
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

// makeArchive creates a zip archive from the specified paths
func (h *FileHandler) makeArchive(paths []string, bulk, recursive bool, sysProcAttr *syscall.SysProcAttr) (string, error) {
	var archiveName string
	var cmd *exec.Cmd
	path := paths[0]

	if bulk {
		archiveName = filepath.Dir(path) + "/" + uuid.New().String() + ".zip"
		dirPath := filepath.Dir(path)
		basePaths := make([]string, len(paths))
		for i, p := range paths {
			basePaths[i] = filepath.Base(p)
		}

		cmd = exec.Command("zip", "-r", archiveName)
		cmd.SysProcAttr = sysProcAttr
		cmd.Args = append(cmd.Args, basePaths...)
		cmd.Dir = dirPath
	} else {
		if recursive {
			archiveName = path + ".zip"
			cmd = exec.Command("zip", "-r", archiveName, filepath.Base(path))
			cmd.SysProcAttr = sysProcAttr
			cmd.Dir = filepath.Dir(path)
		} else {
			archiveName = path
		}
	}

	if bulk || recursive {
		err := cmd.Run()
		if err != nil {
			return "", err
		}
	}

	return archiveName, nil
}

// createMultipartBody creates a multipart form body for file upload
func (h *FileHandler) createMultipartBody(output []byte, filePath string, useBlob, isRecursive bool) (bytes.Buffer, string, error) {
	if useBlob {
		return *bytes.NewBuffer(output), "", nil
	}

	var requestBody bytes.Buffer
	writer := multipart.NewWriter(&requestBody)

	fileWriter, err := writer.CreateFormFile("content", filePath)
	if err != nil {
		return bytes.Buffer{}, "", err
	}

	_, err = fileWriter.Write(output)
	if err != nil {
		return bytes.Buffer{}, "", err
	}

	if isRecursive {
		err = writer.WriteField("name", filePath)
		if err != nil {
			return bytes.Buffer{}, "", err
		}
	}

	_ = writer.Close()

	return requestBody, writer.FormDataContentType(), nil
}

// fileUpload uploads the file to the server
func (h *FileHandler) fileUpload(uploadURL string, useBlob bool, body bytes.Buffer, contentType string) ([]byte, int, error) {
	if useBlob {
		return utils.Put(uploadURL, body, 0)
	}

	if h.apiSession == nil {
		return nil, 0, errors.New("API session not available")
	}

	return h.apiSession.MultipartRequest(uploadURL, body, contentType, time.Duration(fileUploadTimeout)*time.Second)
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

// fetchFromURL downloads content from a URL
func (h *FileHandler) fetchFromURL(contentURL string) ([]byte, error) {
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		log.Error().Msgf("Failed to download content from URL: %d %s", resp.StatusCode, parsedRequestURL)
		return nil, errors.New("downloading content failed")
	}

	content, err := io.ReadAll(resp.Body)
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
