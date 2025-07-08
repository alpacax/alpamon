package runner

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/logger"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/gorilla/websocket"
)

type FtpClient struct {
	conn             *websocket.Conn
	requestHeader    http.Header
	url              string
	homeDirectory    string
	workingDirectory string
	log              logger.FtpLogger
}

func NewFtpClient(data FtpConfigData) *FtpClient {
	headers := http.Header{
		"Origin":     {data.ServerURL},
		"User-Agent": {utils.GetUserAgent("alpamon")},
	}

	return &FtpClient{
		requestHeader:    headers,
		url:              strings.Replace(data.ServerURL, "http", "ws", 1) + data.URL,
		homeDirectory:    data.HomeDirectory,
		workingDirectory: data.HomeDirectory,
		log:              data.Logger,
	}
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

	<-ctx.Done()
}

func (fc *FtpClient) read(ctx context.Context, cancel context.CancelFunc) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
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

			var content FtpContent
			err = json.Unmarshal(message, &content)
			if err != nil {
				fc.log.Debug().Err(err).Msg("Failed to unmarshal websocket message.")
				cancel()
				return
			}

			result := FtpResult{
				Command: content.Command,
				Success: true,
			}

			data, err := fc.handleFtpCommand(content.Command, content.Data)
			if err != nil {
				result.Success = false
				result.Data, result.Code = GetFtpErrorCode(content.Command, data)
			} else {
				result.Code = returnCodes[content.Command].Success
				result.Data = data
			}

			response, err := json.Marshal(result)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				fc.log.Debug().Err(err).Msg("Failed to marshal response.")
				cancel()
				return
			}

			err = fc.conn.WriteMessage(websocket.TextMessage, response)
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
		_ = fc.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
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
		return fc.mv(data.Src, data.Dst)
	case Cp:
		return fc.cp(data.Src, data.Dst)
	case Chmod:
		return fc.chmod(data.Path, data.Mode, data.Recursive)
	case Chown:
		return fc.chown(data.Path, data.Username, data.Groupname, data.Recursive)
	default:
		return CommandResult{}, fmt.Errorf("unknown FTP command: %s", command)
	}
}

func (fc *FtpClient) parsePath(path string) string {
	if strings.HasPrefix(path, "~") {
		path = strings.Replace(path, "~", fc.workingDirectory, 1)
	}

	absPath := path
	if !filepath.IsAbs(path) {
		absPath = filepath.Join(fc.workingDirectory, path)
	}

	parsedPath := filepath.Clean(absPath)
	return parsedPath
}

func (fc *FtpClient) list(rootDir string, depth int, showHidden bool) (CommandResult, error) {
	path := fc.parsePath(rootDir)
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
		Path:     path,
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

	if info.Mode()&os.ModeSymlink != 0 {
		return nil
	}

	permString, permOctal, owner, group, err := utils.GetFileInfo(info, fullPath)
	if err != nil {
		result := fc.handleListErrorResult(fullPath, err)

		return &result
	}

	modTime := info.ModTime()
	child := &CommandResult{
		Name:             entry.Name(),
		Path:             fullPath,
		Code:             returnCodes[List].Success,
		ModTime:          &modTime,
		PermissionString: permString,
		PermissionOctal:  permOctal,
		Owner:            owner,
		Group:            group,
	}

	if entry.IsDir() {
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
		Path:    path,
		Message: err.Error(),
	}
	_, result.Code = GetFtpErrorCode(List, result)

	return result
}

func (fc *FtpClient) mkd(path string) (CommandResult, error) {
	path = fc.parsePath(path)

	err := os.Mkdir(path, 0755)
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
	path = fc.parsePath(path)

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
	return CommandResult{
		Message: fmt.Sprintf("Current working directory: %s.", fc.workingDirectory),
		Path:    fc.workingDirectory,
	}, nil
}

func (fc *FtpClient) dele(path string) (CommandResult, error) {
	path = fc.parsePath(path)

	err := os.Remove(path)
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
	path = fc.parsePath(path)

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	var err error
	if recursive {
		err = os.RemoveAll(path)
	} else {
		err = os.Remove(path)
	}

	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Message: fmt.Sprintf("Delete %s successfully.", path),
	}, nil
}

func (fc *FtpClient) mv(src, dst string) (CommandResult, error) {
	src = fc.parsePath(src)
	dst = fc.parsePath(dst)

	err := os.Rename(src, dst)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Dst:     dst,
		Message: fmt.Sprintf("Move %s to %s.", src, dst),
	}, nil
}

func (fc *FtpClient) cp(src, dst string) (CommandResult, error) {
	src = fc.parsePath(src)
	dst = filepath.Join(fc.parsePath(dst), filepath.Base(src))

	info, err := os.Stat(src)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	if info.IsDir() {
		return fc.cpDir(src, dst)
	}
	return fc.cpFile(src, dst)
}

func (fc *FtpClient) cpDir(src, dst string) (CommandResult, error) {
	err := utils.CopyDir(src, dst)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Dst:     dst,
		Message: fmt.Sprintf("Copy %s to %s.", src, dst),
	}, nil
}

func (fc *FtpClient) cpFile(src, dst string) (CommandResult, error) {
	err := utils.CopyFile(src, dst)
	if err != nil {
		return CommandResult{
			Message: err.Error(),
		}, err
	}

	return CommandResult{
		Dst:     dst,
		Message: fmt.Sprintf("Copy %s to %s.", src, dst),
	}, nil
}

func (fc *FtpClient) chmod(path, mode string, recursive bool) (CommandResult, error) {
	path = fc.parsePath(path)
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
	path = fc.parsePath(path)

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
