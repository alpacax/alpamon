package file

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/executor/handlers/common"
	"github.com/alpacax/alpamon/v2/pkg/scheduler"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

// FileHandler handles file transfer commands
type FileHandler struct {
	*common.BaseHandler
	apiSession common.APISession
}

// base64Reader wraps a base64 decoder and re-tags decode errors for clearer diagnostics.
type base64Reader struct {
	r io.Reader
}

func (b *base64Reader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err != nil && err != io.EOF {
		return n, fmt.Errorf("failed to decode base64 content: %w", err)
	}
	return n, err
}

// limitedReadCloser wraps an io.ReadCloser and returns an error when the byte
// limit is exceeded, avoiding the nil-ResponseWriter panic of http.MaxBytesReader.
// r is wrapped with io.LimitReader(rc, limit+1) so the overshoot is at most 1 byte.
type limitedReadCloser struct {
	r     io.Reader
	rc    io.ReadCloser
	limit int64
	read  int64
}

// NewFileHandler creates a new file handler
func NewFileHandler(cmdExecutor common.CommandExecutor, apiSession common.APISession) *FileHandler {
	h := &FileHandler{
		BaseHandler: common.NewBaseHandler(
			common.FileTransfer,
			[]common.CommandType{
				common.Upload,
				common.Download,
				common.Rm,
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
	case common.Rm.String():
		code, message = h.handleRm(args)
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

	case common.Rm.String():
		if args.Path == "" {
			return fmt.Errorf("rm: path is required")
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

	// Upload accepts looser group matching; supplementary-group
	// enforcement applies to downloads via ValidateGroup=true.
	sysProcAttr, homeDirectory, err := h.demoteWithHomeDir(args.Username, args.Groupname, false, args.HomeDirectory)
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

	src, size, err := readFileAs(ctx, name, sysProcAttr)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read file for upload.")
		return 1, err.Error()
	}

	// fileUpload owns src.Close() so a non-zero exit from the demoted-cat
	// reader (cmdReadCloser) can be propagated through the upload pipeline.
	statusCode, err := h.fileUpload(args, src, size, filepath.Base(name), recursive)
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
func (h *FileHandler) handleDownload(ctx context.Context, args *common.CommandArgs) (int, string, error) {
	log.Debug().
		Str("username", args.Username).
		Str("groupname", args.Groupname).
		Str("path", args.Path).
		Msg("Downloading file")

	var code int
	var message string

	if len(args.Files) == 0 {
		// Download enforces supplementary-group membership so a requested
		// GID cannot widen filesystem access beyond what the user has.
		sysProcAttr, _, err := h.demoteWithHomeDir(args.Username, args.Groupname, true, args.HomeDirectory)
		if err != nil {
			log.Error().Err(err).Msg("Failed to demote user.")
			return 1, err.Error(), nil
		}
		code, message = h.fileDownload(ctx, args, sysProcAttr)
		h.statFileTransfer(code, upload, message, args)
	} else {
		// Each file entry may target a different user/group, so demote
		// per file to get the correct sysProcAttr and home directory
		// for that entry. Reusing the outer args.Username's demotion
		// would mix up ownership and containment roots on Unix.
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
				HomeDirectory:  args.HomeDirectory,
			}
			sysProcAttr, _, err := h.demoteWithHomeDir(cmdArgs.Username, cmdArgs.Groupname, true, cmdArgs.HomeDirectory)
			if err != nil {
				log.Error().Err(err).Str("username", cmdArgs.Username).Msg("Failed to demote user.")
				code = 1
				message = err.Error()
				h.statFileTransfer(code, upload, message, cmdArgs)
				continue
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
	src, err := h.getFileData(ctx, args)
	if err != nil {
		return 1, err.Error()
	}
	defer func() { _ = src.Close() }()

	// Paths arrive in wire format from the web client.
	downloadPath, err := utils.SanitizePath(utils.FromWirePath(args.Path))
	if err != nil {
		return 1, err.Error()
	}
	args.Path = downloadPath

	if !args.AllowOverwrite && utils.FileExists(args.Path) {
		return 1, fmt.Sprintf("%s already exists.", args.Path)
	}

	// Write file, preserving privilege demotion on Unix when available.
	if err := writeFileAs(ctx, args.Path, src, sysProcAttr); err != nil {
		log.Error().Err(err).Msg("Failed to write file.")
		if os.IsPermission(err) || errors.Is(err, syscall.EACCES) {
			return 1, "You do not have permission to write to the directory, or directory does not exist"
		}
		return 1, err.Error()
	}

	if args.AllowUnzip {
		if rc := utils.OpenIfZip(args.Path, filepath.Ext(args.Path)); rc != nil {
			err := utils.UnzipReader(rc, filepath.Dir(args.Path))
			_ = rc.Close()
			if err != nil {
				log.Error().Err(err).Msg("Failed to unzip file.")
				return 1, err.Error()
			}
			// lgtm[go/path-injection]: args.Path sanitized via SanitizePath, which
			// rejects null bytes, UNC/device prefixes, and literal ".." after
			// cleaning. Wire input is admin-authenticated.
			_ = os.Remove(args.Path) // lgtm[go/path-injection]
		}
	}

	return 0, fmt.Sprintf("Successfully downloaded %s.", args.Path)
}

// stagePrefix is the fixed, non-user-controlled directory-plus-name prefix of
// the alpacon-server exec staging path; only the trailing hex and ".sh" vary.
const stagePrefix = "/tmp/.alpacon-exec-"

// stagedExecScriptPattern matches the alpacon-server exec staging path,
// derived from stagePrefix so the two never drift. The "rm" that cleans up
// this script is an internal command, which bypasses command signing, so this
// pattern is the only barrier between it and an unsigned arbitrary-file-
// deletion primitive—do not loosen it.
var stagedExecScriptPattern = regexp.MustCompile(
	"^" + regexp.QuoteMeta(stagePrefix) + `[0-9a-f]+\.sh$`,
)

// isStagePath guards handleRm; split out so the pattern match (after
// path.Clean folds any traversal) has standalone test coverage. Uses
// path.Clean, not filepath.Clean: the staged path is always a POSIX path
// from the server, so cleaning must stay slash-based regardless of agent OS.
func isStagePath(p string) bool {
	return stagedExecScriptPattern.MatchString(path.Clean(p))
}

// removeStaged deletes filePath with `rm -f` semantics (already absent counts
// as success). Callers must verify filePath via isStagePath first.
func removeStaged(filePath string) (int, string) {
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Sprintf("%s does not exist; nothing to remove.", filePath)
		}
		return 1, err.Error()
	}
	return 0, fmt.Sprintf("Successfully removed %s.", filePath)
}

// handleRm removes a staged exec wrapper script left behind when the command
// it wraps never ran (rejected or expired). See stagedExecScriptPattern.
func (h *FileHandler) handleRm(args *common.CommandArgs) (int, string) {
	log.Debug().Str("path", args.Path).Msg("Removing staged exec script")
	cleaned := path.Clean(args.Path)
	// HasPrefix pins cleaned to the fixed staging prefix (the barrier the
	// path-injection scanner recognizes on the value that reaches os.Remove);
	// isStagePath then enforces the exact <hex>.sh format.
	if !strings.HasPrefix(cleaned, stagePrefix) || !isStagePath(cleaned) {
		log.Warn().Str("path", args.Path).Msg("Rejected rm outside exec staging namespace")
		return 1, fmt.Sprintf("rm: refusing to remove path outside staging namespace: %s", args.Path)
	}

	return removeStaged(cleaned)
}

// demoteWithHomeDir demotes privilege and returns the home directory.
// validateGroup enforces that the requested group is a supplementary
// group of the user. Required on Unix download paths to prevent
// using an arbitrary GID for filesystem access; off on upload paths
// which accept looser group matching.
//
// Home directory is resolved in descending priority:
//  1. utils.Demote result (Unix, running as root)
//  2. os/user.Lookup on the given username
//  3. fallbackHome (typically args.HomeDirectory carried in the
//     protocol message from alpacon-server)
//
// The fallback exists so Windows and non-root Unix paths do not end
// up with an empty home, which would otherwise cause relative paths
// and tilde expansion to resolve against the process CWD and yield
// unpredictable results.
func (h *FileHandler) demoteWithHomeDir(username, groupname string, validateGroup bool, fallbackHome string) (*syscall.SysProcAttr, string, error) {
	result, err := utils.Demote(username, groupname, utils.DemoteOptions{ValidateGroup: validateGroup})
	if err != nil {
		return nil, "", err
	}
	if result != nil {
		return result.SysProcAttr, result.User.HomeDir, nil
	}
	if username != "" {
		if u, err := user.Lookup(username); err == nil && u.HomeDir != "" {
			return nil, u.HomeDir, nil
		}
	}
	return nil, fallbackHome, nil
}

// parsePaths converts wire-format paths to native OS paths and
// sanitizes them. homeDirectory is used as the anchor for tilde
// expansion (`~/foo`) and as the base for joining relative paths;
// it is NOT a containment root. SanitizePath rejects null bytes,
// Windows UNC/device/extended-length prefixes (`\\...`), and any
// literal ".." that survives filepath.Clean — that is the path-shape
// validation performed here. Caller-side privilege demotion (Unix)
// and Alpacon RBAC (both platforms) handle access control. Returns
// the sanitized native paths plus bulk/recursive flags inferred from
// the input.
func (h *FileHandler) parsePaths(homeDirectory string, pathList []string) ([]string, bool, bool, error) {
	paths := make([]string, len(pathList))
	for i, path := range pathList {
		// Paths from the web client arrive in wire format (POSIX-like
		// with a leading "/"). Convert to a native OS path before any
		// filepath.IsAbs / Join work, otherwise Windows drive-letter
		// paths like "/C:/Users/foo" get joined to homeDirectory and
		// produce "C:\C:\Users\foo".
		path = utils.FromWirePath(path)

		if strings.HasPrefix(path, "~") {
			path = strings.Replace(path, "~", homeDirectory, 1)
		}

		if !filepath.IsAbs(path) {
			path = filepath.Join(homeDirectory, path)
		}

		sanitized, err := utils.SanitizePath(path)
		if err != nil {
			return nil, false, false, err
		}
		paths[i] = sanitized
	}

	isBulk := len(pathList) > 1
	isRecursive := false

	if !isBulk {
		fileInfo, err := os.Stat(paths[0])
		if err != nil {
			return nil, false, false, err
		}
		isRecursive = fileInfo.IsDir()
	}

	return paths, isBulk, isRecursive, nil
}

// makeArchive creates a zip archive from the specified paths using Go's archive/zip.
// It returns the archive file path, a cleanup path (non-empty only for temp archives), and any error.
// cleanupPath is always derived from os.TempDir() and never from user input,
// ensuring os.Remove(cleanupPath) is safe from path-injection.
func (h *FileHandler) makeArchive(ctx context.Context, paths []string, bulk, recursive bool, sysProcAttr *syscall.SysProcAttr) (string, string, error) {
	path := paths[0]

	if !bulk && !recursive {
		return path, "", nil
	}

	archiveName := filepath.Join(os.TempDir(), uuid.New().String()+".zip")

	if err := utils.CreateZip(archiveName, paths, recursive || bulk); err != nil {
		_ = os.Remove(archiveName)
		return "", "", err
	}

	return archiveName, archiveName, nil
}

// fileUpload uploads the file to the server. Owns src.Close():
//   - UseBlob path: closes src after the synchronous PUT.
//   - Multipart path: hands ownership to buildMultipartStream's producer goroutine
//     (it Close()s src and propagates non-nil errors via pw.CloseWithError).
//   - Pre-handoff failures: closes src directly so it never leaks.
func (h *FileHandler) fileUpload(args *common.CommandArgs, src io.ReadCloser, size int64, fileName string, recursive bool) (int, error) {
	if args.UseBlob {
		// Strip Closer so http.Client.Do can't close src before us—we own
		// the close so the demoted-cat reader's non-zero exit (EACCES/ENOENT)
		// surfaces via Close(), and *os.File on Windows is not double-closed
		// (returns os.ErrClosed on the second Close, which would otherwise be
		// reported as a failed upload even though the PUT succeeded).
		_, code, err := utils.Put(args.Content, io.NopCloser(src), size, 0)
		if cerr := src.Close(); err == nil && cerr != nil {
			return code, cerr
		}
		return code, err
	}

	if h.apiSession == nil {
		_ = src.Close()
		return 0, errors.New("API session not available")
	}

	body, contentType, contentLength, err := buildMultipartStream(src, fileName, recursive, size)
	if err != nil {
		_ = src.Close()
		return 0, err
	}
	defer func() { _ = body.Close() }()

	// fileUploadTimeout is a seconds count; Session.MultipartRequest applies
	// *time.Second internally, so pass the bare Duration (matches sibling
	// callers like apiSession.Post(url, data, 5)).
	_, code, err := h.apiSession.MultipartRequest(args.Content, body, contentType, contentLength, time.Duration(fileUploadTimeout))
	return code, err
}

// getFileData returns a streaming reader for the file content. Caller owns Close.
func (h *FileHandler) getFileData(ctx context.Context, args *common.CommandArgs) (io.ReadCloser, error) {
	switch args.Type {
	case "url":
		return h.fetchFromURL(ctx, args.Content)
	case "text":
		return io.NopCloser(strings.NewReader(args.Content)), nil
	case "base64":
		return io.NopCloser(&base64Reader{r: base64.NewDecoder(base64.StdEncoding, strings.NewReader(args.Content))}), nil
	default:
		return nil, fmt.Errorf("unknown file type: %s", args.Type)
	}
}

// fetchFromURL returns the response body. Caller must Close to release the connection.
func (h *FileHandler) fetchFromURL(ctx context.Context, contentURL string) (io.ReadCloser, error) {
	parsedRequestURL, err := url.Parse(contentURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL '%s': %w", contentURL, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedRequestURL.String(), nil)
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

	// lgtm[go/request-forgery]: Intentional - Admin-specified URL for file content
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

	// Apply size cap only when configured (0 = unlimited).
	if limit := config.GlobalSettings.MaxDownloadBytes; limit > 0 {
		if resp.ContentLength > limit {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("download too large: %d bytes (max %d)", resp.ContentLength, limit)
		}
		// limitedReadCloser catches servers that lie in Content-Length or use chunked encoding.
		return &limitedReadCloser{r: io.LimitReader(resp.Body, limit+1), rc: resp.Body, limit: limit}, nil
	}

	return resp.Body, nil
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

func (l *limitedReadCloser) Read(p []byte) (int, error) {
	n, err := l.r.Read(p)
	l.read += int64(n)
	if l.read > l.limit {
		_ = l.rc.Close()
		return n, fmt.Errorf("download too large: exceeds max %d bytes", l.limit)
	}
	return n, err
}

func (l *limitedReadCloser) Close() error {
	return l.rc.Close()
}
