package runner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/alpacax/alpamon/v2/pkg/config"
	"github.com/alpacax/alpamon/v2/pkg/logger"
	"github.com/alpacax/alpamon/v2/pkg/utils"
	"github.com/gorilla/websocket"
)

// ftpWriteTimeout bounds a single WriteMessage so a stalled peer that stops
// draining can't wedge the pipeline; one response to a live peer needs only seconds.
const ftpWriteTimeout = 30 * time.Second

type FtpClient struct {
	conn             *websocket.Conn
	requestHeader    http.Header
	url              string
	homeDirectory    string
	workingDirectory string
	log              logger.FtpLogger
	commandChan      chan []byte
	responseChan     chan []byte
	writeTimeout     time.Duration
	execute          func(command FtpCommand, data FtpData) (CommandResult, error)
}

func NewFtpClient(data FtpConfigData) *FtpClient {
	headers := http.Header{
		"Origin":     {data.ServerURL},
		"User-Agent": {utils.GetUserAgent("alpamon")},
	}

	homeDir := utils.FromWirePath(data.HomeDirectory)
	if runtime.GOOS == "windows" && homeDir == "" {
		// On Windows alpamon runs as SYSTEM with no privilege demotion,
		// so an empty home directory would let relative paths resolve
		// against the service process CWD with full SYSTEM rights,
		// which is both confusing and unsafe. On Unix the demoted
		// process's filesystem ACLs make the same scenario benign, so
		// the check is Windows-only. Refuse to open the session here
		// rather than surface the surprise on every subsequent command.
		data.Logger.Debug().Msg("Refusing to open WebFTP session with empty home directory on Windows.")
		return nil
	}
	client := &FtpClient{
		requestHeader:    headers,
		url:              data.URL,
		homeDirectory:    homeDir,
		workingDirectory: homeDir,
		log:              data.Logger,
		commandChan:      make(chan []byte, 1),
		responseChan:     make(chan []byte, 1),
		writeTimeout:     ftpWriteTimeout,
	}
	client.execute = client.handleFtpCommand
	return client
}

func (fc *FtpClient) RunFtpBackground() {
	fc.log.Debug().Msg("Opening websocket for ftp session.")

	var err error
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !config.GlobalSettings.SSLVerify,
		},
	}
	fc.conn, _, err = dialer.Dial(fc.url, fc.requestHeader)
	if err != nil {
		fc.log.Debug().Err(err).Msgf("Failed to connect to pty websocket at %s.", fc.url)
		return
	}
	defer fc.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go fc.read(ctx, cancel)
	go fc.handleCommands(ctx, cancel)
	go fc.write(ctx, cancel)

	<-ctx.Done()
}

func (fc *FtpClient) read(ctx context.Context, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// A parked ReadMessage is woken only by conn.Close() (RunFtpBackground's deferred close()), not cancel().
			_, message, err := fc.conn.ReadMessage()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					fc.log.Debug().Err(err).Msg("Failed to read from ftp websocket.")
				}
				cancel()
				return
			}

			select {
			case fc.commandChan <- message:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (fc *FtpClient) handleCommands(ctx context.Context, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case message := <-fc.commandChan:
			// A buffered command can be selected after cancel(); don't start a new command during shutdown.
			if ctx.Err() != nil {
				return
			}
			var content FtpContent
			if err := json.Unmarshal(message, &content); err != nil {
				fc.log.Debug().Err(err).Msg("Failed to unmarshal websocket message.")
				cancel()
				return
			}

			result := FtpResult{
				Command: content.Command,
				Success: true,
			}

			data, err := fc.execute(content.Command, content.Data)
			if err != nil {
				result.Success = false
				result.Data, result.Code = GetFtpErrorCode(content.Command, data)
			} else {
				result.Code = returnCodes[content.Command].Success
				result.Data = data
			}

			response, err := json.Marshal(result)
			if err != nil {
				fc.log.Debug().Err(err).Msg("Failed to marshal response.")
				cancel()
				return
			}

			select {
			case fc.responseChan <- response:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (fc *FtpClient) write(ctx context.Context, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		case response := <-fc.responseChan:
			// A buffered response can be selected after cancel(); don't write during shutdown.
			if ctx.Err() != nil {
				return
			}
			// Reset each write since the deadline is absolute; zero disables it for test literals.
			if fc.writeTimeout > 0 {
				_ = fc.conn.SetWriteDeadline(time.Now().Add(fc.writeTimeout))
			}
			err := fc.conn.WriteMessage(websocket.TextMessage, response)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					fc.log.Debug().Err(err).Msg("Failed to send websocket message.")
				}
				cancel()
				return
			}
		}
	}
}

func (fc *FtpClient) close() {
	if fc.conn != nil {
		// Use WriteControl, not WriteMessage: the write pump may still be mid-WriteMessage here, and gorilla allows only one concurrent writer.
		_ = fc.conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(5*time.Second),
		)
		_ = fc.conn.Close()
	}

	fc.log.Debug().Msg("Websocket connection for ftp has been closed.")
	os.Exit(1)
}

func (fc *FtpClient) handleFtpCommand(command FtpCommand, data FtpData) (CommandResult, error) {
	switch command {
	case List:
		return fc.list(data.Path, data.Depth, data.ShowHidden)
	case Mkd:
		return fc.mkd(data.Path)
	case Cwd:
		return fc.cwd(data.Path)
	case Pwd:
		return fc.pwd()
	case Dele:
		return fc.dele(data.Path)
	case Rmd:
		return fc.rmd(data.Path, data.Recursive)
	case Mv:
		return fc.mv(data.Src, data.Dst, data.AllowOverwrite)
	case Cp:
		return fc.cp(data.Src, data.Dst, data.AllowOverwrite)
	case Chmod:
		return fc.chmod(data.Path, data.Mode, data.Recursive)
	case Chown:
		return fc.chown(data.Path, data.Username, data.Groupname, data.Recursive)
	default:
		return CommandResult{}, fmt.Errorf("unknown FTP command: %s", command)
	}
}

// parsePath takes a wire-format path from the web client and returns a
// native OS absolute path suitable for os.* calls. Use utils.ToWirePath() when
// placing the resulting path back into a response.
func (fc *FtpClient) parsePath(path string) (string, error) {
	if strings.ContainsRune(path, '\x00') {
		return "", fmt.Errorf("invalid argument: path contains null byte")
	}

	path = utils.FromWirePath(path)

	if strings.HasPrefix(path, "~") {
		path = strings.Replace(path, "~", fc.workingDirectory, 1)
	}

	if !filepath.IsAbs(path) {
		path = filepath.Join(fc.workingDirectory, path)
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		absPath = path
	}

	cleanPath := filepath.Clean(absPath)

	// Reject Windows UNC, device, and extended-length namespace paths
	// (`\\server\share`, `\\.\PHYSICALDRIVE0`, `\\?\...`). They have no
	// legitimate WebFTP use; without this check a wire path could make
	// alpamon (SYSTEM on Windows) authenticate to a hostile SMB server
	// or open raw devices. Universal — the prefix has no legitimate
	// meaning on Unix either, so no platform branch is needed.
	if strings.HasPrefix(cleanPath, `\\`) {
		return "", fmt.Errorf("%s: UNC and device paths are not allowed", ErrInvalidArgument)
	}

	if runtime.GOOS == "windows" {
		// WebFTP on Windows runs as the service account (typically
		// SYSTEM) because privilege demotion is not yet implemented;
		// on Unix the demoted-process OS-level ACLs provide per-user
		// scoping. Either way, parsePath does not enforce a
		// containment boundary here. Access control is delegated to
		// OS privileges and to Alpacon RBAC.
		return cleanPath, nil
	}

	// Unix: enforce that the resolved path stays under "/". OS-level
	// ACLs from privilege demotion provide the finer-grained scoping.
	rel, err := filepath.Rel("/", cleanPath)
	if err != nil {
		return "", fmt.Errorf("%s: invalid path: %w", ErrInvalidArgument, err)
	}
	return filepath.Join("/", rel), nil
}

func (fc *FtpClient) list(rootDir string, depth int, showHidden bool) (CommandResult, error) {
	path, err := fc.parsePath(rootDir)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}
	cmdResult, err := fc.listRecursive(path, depth, 0, showHidden)
	return cmdResult, err
}

func (fc *FtpClient) listRecursive(path string, depth, current int, showHidden bool) (CommandResult, error) {
	if depth > 3 {
		return CommandResult{
			Message: ErrTooLargeDepth,
		}, fmt.Errorf("%s", ErrTooLargeDepth)
	}

	result := CommandResult{
		Name:     filepath.Base(path),
		Type:     "folder",
		Path:     utils.ToWirePath(path),
		ModTime:  nil,
		Children: []CommandResult{},
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return fc.handleListErrorResult(path, err), nil
	}

	for _, entry := range entries {
		child := fc.getDiretoryStructure(entry, path, depth, current, showHidden)
		if child != nil {
			result.Children = append(result.Children, *child)
		}
	}

	dirInfo, err := os.Stat(path)
	if err != nil {
		result.Message = err.Error()
		_, result.Code = GetFtpErrorCode(List, result)
	} else {
		modTime := dirInfo.ModTime()
		permString, permOctal, owner, group, err := utils.GetFileInfo(dirInfo, path)
		if err != nil {
			result.Message = err.Error()
			_, result.Code = GetFtpErrorCode(List, result)
		}

		result.PermissionString = permString
		result.PermissionOctal = permOctal
		result.Owner = owner
		result.Group = group
		result.ModTime = &modTime
		result.Code = returnCodes[List].Success
	}

	return result, nil
}

func (fc *FtpClient) getDiretoryStructure(entry os.DirEntry, path string, depth, current int, showHidden bool) *CommandResult {
	if !showHidden && strings.HasPrefix(entry.Name(), ".") {
		return nil
	}

	fullPath := filepath.Join(path, entry.Name())
	info, err := os.Lstat(fullPath)
	if err != nil {
		result := fc.handleListErrorResult(fullPath, err)

		return &result
	}

	isSymlink := info.Mode()&os.ModeSymlink != 0
	var target string
	var targetInfo os.FileInfo

	if isSymlink {
		target, err = os.Readlink(fullPath)
		if err != nil {
			result := fc.handleListErrorResult(fullPath, err)
			return &result
		}
		// Get info of the target file (follow symlink)
		targetInfo, _ = os.Stat(fullPath)
	}

	permString, permOctal, owner, group, err := utils.GetFileInfo(info, fullPath)
	if err != nil {
		result := fc.handleListErrorResult(fullPath, err)

		return &result
	}

	modTime := info.ModTime()
	child := &CommandResult{
		Name:             entry.Name(),
		Path:             utils.ToWirePath(fullPath),
		Code:             returnCodes[List].Success,
		ModTime:          &modTime,
		PermissionString: permString,
		PermissionOctal:  permOctal,
		Owner:            owner,
		Group:            group,
	}

	if isSymlink {
		child.Type = "symlink"
		child.Target = utils.ToWirePath(target)
		if targetInfo != nil {
			child.Size = targetInfo.Size()
		}
	} else if entry.IsDir() {
		child.Type = "folder"
		if current < depth-1 {
			childResult, err := fc.listRecursive(fullPath, depth, current+1, showHidden)
			if err != nil {
				return &childResult
			}
			child = &childResult
		}
	} else {
		child.Type = "file"
		child.Code = returnCodes[List].Success
		child.Size = info.Size()
	}

	return child
}

func (fc *FtpClient) handleListErrorResult(path string, err error) CommandResult {
	result := CommandResult{
		Name:    filepath.Base(path),
		Path:    utils.ToWirePath(path),
		Message: err.Error(),
	}
	_, result.Code = GetFtpErrorCode(List, result)

	return result
}

func (fc *FtpClient) mkd(path string) (CommandResult, error) {
	path, err := fc.parsePath(path)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}

	err = os.Mkdir(path, 0755)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Message: fmt.Sprintf("Make %s successfully.", path),
	}, nil
}

func (fc *FtpClient) cwd(path string) (CommandResult, error) {
	path, err := fc.parsePath(path)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	if !info.IsDir() {
		return CommandResult{
			Message: "not a directory",
		}, fmt.Errorf("not a directory")
	}

	fc.workingDirectory = path

	return CommandResult{
		Message: fmt.Sprintf("Change working directory to %s.", path),
	}, nil
}

func (fc *FtpClient) pwd() (CommandResult, error) {
	wire := utils.ToWirePath(fc.workingDirectory)
	return CommandResult{
		Message: fmt.Sprintf("Current working directory: %s.", wire),
		Path:    wire,
	}, nil
}

func (fc *FtpClient) dele(path string) (CommandResult, error) {
	path, err := fc.parsePath(path)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}

	err = os.Remove(path)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Message: fmt.Sprintf("Delete %s successfully.", path),
	}, nil
}

func (fc *FtpClient) rmd(path string, recursive bool) (CommandResult, error) {
	path, err := fc.parsePath(path)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}

	if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
		return CommandResult{
			Message: statErr.Error(),
		}, statErr
	}

	var rmErr error
	if recursive {
		rmErr = os.RemoveAll(path)
	} else {
		rmErr = os.Remove(path)
	}

	if rmErr != nil {
		return CommandResult{
			Message: rmErr.Error(),
		}, rmErr
	}

	return CommandResult{
		Message: fmt.Sprintf("Delete %s successfully.", path),
	}, nil
}

func (fc *FtpClient) mv(src, dst string, allowOverwrite bool) (CommandResult, error) {
	var err error
	src, err = fc.parsePath(src)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}
	dst, err = fc.parsePath(dst)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}

	if !allowOverwrite {
		_, err := os.Stat(dst)
		switch {
		case err == nil:
			dst = filepath.Clean(utils.GetCopyPath(src, dst))
		case os.IsNotExist(err):
		default:
			return CommandResult{
				Message: err.Error(),
			}, err
		}
	}

	err = os.Rename(src, dst)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Dst:     utils.ToWirePath(dst),
		Message: fmt.Sprintf("Move %s to %s.", utils.ToWirePath(src), utils.ToWirePath(dst)),
	}, nil
}

func (fc *FtpClient) cp(src, dst string, allowOverwrite bool) (CommandResult, error) {
	var err error
	src, err = fc.parsePath(src)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}
	dst, err = fc.parsePath(dst)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}

	if src == dst {
		dst = filepath.Clean(utils.GetCopyPath(src, dst))
	}

	if !allowOverwrite {
		_, err := os.Stat(dst)
		switch {
		case err == nil:
			dst = filepath.Clean(utils.GetCopyPath(src, dst))
		case os.IsNotExist(err):
		default:
			return CommandResult{
				Message: err.Error(),
			}, err
		}
	}

	info, err := os.Stat(src)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	if info.IsDir() {
		return fc.cpDir(src, dst, allowOverwrite)
	}

	return fc.cpFile(src, dst, allowOverwrite)
}

func (fc *FtpClient) cpDir(src, dst string, allowOverwrite bool) (CommandResult, error) {
	err := utils.CopyDir(src, dst, allowOverwrite)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Dst:     utils.ToWirePath(dst),
		Message: fmt.Sprintf("Copy %s to %s.", utils.ToWirePath(src), utils.ToWirePath(dst)),
	}, nil
}

func (fc *FtpClient) cpFile(src, dst string, allowOverwrite bool) (CommandResult, error) {
	err := utils.CopyFile(src, dst, allowOverwrite)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Dst:     utils.ToWirePath(dst),
		Message: fmt.Sprintf("Copy %s to %s.", utils.ToWirePath(src), utils.ToWirePath(dst)),
	}, nil
}

func (fc *FtpClient) chmod(path, mode string, recursive bool) (CommandResult, error) {
	if runtime.GOOS == "windows" {
		msg := fmt.Sprintf("chmod is %s. Windows uses ACLs instead of POSIX modes.", ErrNotSupported)
		return CommandResult{Message: msg}, fmt.Errorf("%s", msg)
	}

	path, err := fc.parsePath(path)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}
	fileMode, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	modePerm := os.FileMode(fileMode)

	msg := ""
	if recursive {
		msg = " recursively"
		err = fc.chmodRecursive(path, modePerm)
	} else {
		err = os.Chmod(path, modePerm)
	}

	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Message: fmt.Sprintf("Changed permissions of %s to %o%s", path, fileMode, msg),
	}, nil
}

func (fc *FtpClient) chmodRecursive(path string, fileMode os.FileMode) error {
	return filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		return os.Chmod(p, fileMode)
	})
}

func (fc *FtpClient) chown(path, username, groupname string, recursive bool) (CommandResult, error) {
	if runtime.GOOS == "windows" {
		msg := fmt.Sprintf("chown is %s. Windows uses SID-based ownership instead of UID/GID.", ErrNotSupported)
		return CommandResult{Message: msg}, fmt.Errorf("%s", msg)
	}

	path, err := fc.parsePath(path)
	if err != nil {
		return CommandResult{Message: err.Error()}, err
	}

	uid, err := utils.LookUpUID(username)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	gid, err := utils.LookUpGID(groupname)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	msg := ""
	if recursive {
		msg = " recursively"
		err = utils.ChownRecursive(path, uid, gid)
	} else {
		err = os.Chown(path, uid, gid)
	}

	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Message: fmt.Sprintf("Changed owner of %s to UID: %d, GID: %d%s", path, uid, gid, msg),
	}, nil
}
