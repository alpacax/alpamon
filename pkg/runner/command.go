package runner

import (
	"archive/zip"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/alpacanetworks/alpamon/pkg/config"
	"github.com/alpacanetworks/alpamon/pkg/scheduler"
	"github.com/alpacanetworks/alpamon/pkg/utils"
	"github.com/alpacanetworks/alpamon/pkg/version"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"gopkg.in/go-playground/validator.v9"
)

const (
	fileUploadTimeout = 60 * 10
)

func NewCommandRunner(wsClient *WebsocketClient, apiSession *scheduler.Session, command Command, data CommandData) *CommandRunner {
	var name string
	if command.ID != "" {
		name = fmt.Sprintf("CommandRunner-%s", strings.Split(command.ID, "-")[0])
	}

	return &CommandRunner{
		name:       name,
		command:    command,
		data:       data,
		wsClient:   wsClient,
		apiSession: apiSession,
		validator:  validator.New(),
	}
}

func (cr *CommandRunner) Run() {
	var exitCode int
	var result string

	log.Debug().Msgf("Received command: %s > %s", cr.command.Shell, cr.command.Line)

	start := time.Now()
	switch cr.command.Shell {
	case "internal":
		exitCode, result = cr.handleInternalCmd()
	case "system":
		exitCode, result = cr.handleShellCmd(cr.command.Line, cr.command.User, cr.command.Group, cr.command.Env)
	default:
		exitCode = 1
		result = "Invalid command shell argument."
	}

	if result != "" && cr.command.ID != "" {
		finURL := fmt.Sprintf(eventCommandFinURL, cr.command.ID)

		payload := &commandFin{
			Success:     exitCode == 0,
			Result:      result,
			ElapsedTime: time.Since(start).Seconds(),
		}
		scheduler.Rqueue.Post(finURL, payload, 10, time.Time{})
	}
}

func (cr *CommandRunner) handleInternalCmd() (int, string) {
	args := strings.Fields(cr.command.Line)
	if len(args) == 0 {
		return 1, "No command provided"
	}

	for i, arg := range args {
		unquotedArg, err := strconv.Unquote(arg)
		if err == nil {
			args[i] = unquotedArg
		}
	}

	var cmd string
	switch args[0] {
	case "upgrade":
		latestVersion := utils.GetLatestVersion()

		if version.Version == latestVersion {
			return 0, fmt.Sprintf("Alpamon is already up-to-date (version: %s)", version.Version)
		}

		if utils.PlatformLike == "debian" {
			cmd = "apt-get update -y && " +
				"apt-get install --only-upgrade alpamon -y"
		} else if utils.PlatformLike == "rhel" {
			cmd = "yum update -y alpamon"
		} else {
			return 1, fmt.Sprintf("Platform '%s' not supported.", utils.PlatformLike)
		}
		log.Debug().Msgf("Upgrading alpamon from %s to %s using command: '%s'...", version.Version, latestVersion, cmd)
		return cr.handleShellCmd(cmd, "root", "root", nil)
	case "commit":
		cr.commit()
		return 0, "Committed system information."
	case "sync":
		cr.sync(cr.data.Keys)
		return 0, "Synchronized system information."
	case "adduser":
		return cr.addUser()
	case "addgroup":
		return cr.addGroup()
	case "deluser":
		return cr.delUser()
	case "delgroup":
		return cr.delGroup()
	case "moduser":
		return cr.modUser()
	case "ping":
		return 0, time.Now().Format(time.RFC3339)
	//case "debug":
	//	TODO : getReporterStats()
	case "download":
		return cr.runFileDownload(args[1])
	case "upload":
		code, message := cr.runFileUpload(args[1])
		statFileTransfer(code, DOWNLOAD, message, cr.data)

		return code, message
	case "openpty":
		data := openPtyData{
			SessionID:     cr.data.SessionID,
			URL:           cr.data.URL,
			Username:      cr.data.Username,
			Groupname:     cr.data.Groupname,
			HomeDirectory: cr.data.HomeDirectory,
			Rows:          cr.data.Rows,
			Cols:          cr.data.Cols,
		}
		err := cr.validateData(data)
		if err != nil {
			return 1, fmt.Sprintf("openpty: Not enough information. %s", err.Error())
		}

		ptyClient := NewPtyClient(cr.data, cr.apiSession)
		go ptyClient.RunPtyBackground()

		return 0, "Spawned a pty terminal."
	case "openftp":
		data := openFtpData{
			SessionID:     cr.data.SessionID,
			URL:           cr.data.URL,
			Username:      cr.data.Username,
			Groupname:     cr.data.Groupname,
			HomeDirectory: cr.data.HomeDirectory,
		}
		err := cr.validateData(data)
		if err != nil {
			return 1, fmt.Sprintf("openftp: Not enough information. %s", err.Error())
		}

		err = cr.openFtp(data)
		if err != nil {
			return 1, fmt.Sprintf("%v", err)
		}

		return 0, "Spawned a ftp terminal."
	case "resizepty":
		if terminals[cr.data.SessionID] != nil {
			err := terminals[cr.data.SessionID].resize(cr.data.Rows, cr.data.Cols)
			if err != nil {
				return 1, err.Error()
			}
			return 0, fmt.Sprintf("Resized terminal for %s to %dx%d.", cr.data.SessionID, cr.data.Cols, cr.data.Rows)
		}
		return 1, "Invalid session ID"
	case "restart":
		target := "alpamon"
		message := "Alpamon will restart in 1 second."
		if len(args) >= 2 {
			target = args[1]
		}

		switch target {
		case "collector":
			log.Info().Msg("Restart collector.")
			cr.wsClient.RestartCollector()
			message = "Collector will be restarted."
		default:
			time.AfterFunc(1*time.Second, func() {
				cr.wsClient.Restart()
			})
		}

		return 0, message
	case "quit":
		time.AfterFunc(1*time.Second, func() {
			cr.wsClient.ShutDown()
		})
		return 0, "Alpamon will shutdown in 1 second."
	case "reboot":
		log.Info().Msg("Reboot request received.")
		time.AfterFunc(1*time.Second, func() {
			cr.handleShellCmd("reboot", "root", "root", nil)
		})

		return 0, "Server will reboot in 1 second"
	case "shutdown":
		log.Info().Msg("Shutdown request received.")
		time.AfterFunc(1*time.Second, func() {
			cr.handleShellCmd("shutdown", "root", "root", nil)
		})

		return 0, "Server will shutdown in 1 second"
	case "update":
		log.Info().Msg("Upgrade system requested.")
		if utils.PlatformLike == "debian" {
			cmd = "apt-get update && apt-get upgrade -y && apt-get autoremove -y"
		} else if utils.PlatformLike == "rhel" {
			cmd = "yum update -y"
		} else if utils.PlatformLike == "darwin" {
			cmd = "brew upgrade"
		} else {
			return 1, fmt.Sprintf("Platform '%s' not supported.", utils.PlatformLike)
		}

		return cr.handleShellCmd(cmd, "root", "root", nil)
	case "restartcoll":
		log.Info().Msg("Restart collector.")
		cr.wsClient.RestartCollector()

		return 0, "Collector will be restarted."
	case "iptables":
		return cr.iptables()
	case "help":
		helpMessage := `
		Available commands:
		package install <package name>: install a system package
		package uninstall <package name>: remove a system package
		upgrade: upgrade alpamon
		restart: restart alpamon
		quit: stop alpamon
		update: update system
		reboot: reboot system
		shutdown: shutdown system
		`
		return 0, helpMessage
	default:
		return 1, fmt.Sprintf("Invalid command %s", args[0])
	}
}

func (cr *CommandRunner) handleShellCmd(command, user, group string, env map[string]string) (exitCode int, result string) {
	spl := strings.Fields(command)
	args := []string{}
	results := ""

	if group == "" {
		group = user
	}

	for _, arg := range spl {
		switch arg {
		case "&&":
			exitCode, result = runCmdWithOutput(args, user, group, env, 0)
			results += result
			// stop executing if command fails
			if exitCode != 0 {
				return exitCode, results
			}
			args = []string{}
		case "||":
			exitCode, result = runCmdWithOutput(args, user, group, env, 0)
			results += result
			// execute next only if command fails
			if exitCode == 0 {
				return exitCode, results
			}
			args = []string{}
		case ";":
			exitCode, result = runCmdWithOutput(args, user, group, env, 0)
			results += result
			args = []string{}
		default:
			if strings.HasSuffix(arg, ";") {
				args = append(args, strings.TrimSuffix(arg, ";"))
				exitCode, result = runCmdWithOutput(args, user, group, env, 0)
				results += result
				args = []string{}
			} else {
				args = append(args, arg)
			}
		}
	}

	if len(args) > 0 {
		exitCode, result = runCmdWithOutput(args, user, group, env, 0)
		results += result
	}

	return exitCode, results
}

func (cr *CommandRunner) commit() {
	commitSystemInfo()
}

func (cr *CommandRunner) sync(keys []string) {
	syncSystemInfo(cr.wsClient.apiSession, keys)
}

func (cr *CommandRunner) addUser() (exitCode int, result string) {
	data := addUserData{
		Username:                cr.data.Username,
		UID:                     cr.data.UID,
		GID:                     cr.data.GID,
		Comment:                 cr.data.Comment,
		HomeDirectory:           cr.data.HomeDirectory,
		HomeDirectoryPermission: cr.data.HomeDirectoryPermission,
		Shell:                   cr.data.Shell,
		Groupname:               cr.data.Groupname,
	}

	err := cr.validateData(data)
	if err != nil {
		return 1, fmt.Sprintf("adduser: Not enough information. %s", err)
	}

	if utils.PlatformLike == "debian" {
		exitCode, result = runCmdWithOutput(
			[]string{
				"/usr/sbin/adduser",
				"--home", data.HomeDirectory,
				"--shell", data.Shell,
				"--uid", strconv.FormatUint(data.UID, 10),
				"--gid", strconv.FormatUint(data.GID, 10),
				"--gecos", data.Comment,
				"--disabled-password",
				data.Username,
			},
			"root", "", nil, 60,
		)
		if exitCode != 0 {
			return exitCode, result
		}

		for _, gid := range cr.data.Groups {
			if gid == data.GID {
				continue
			}
			// get groupname from gid
			group, err := user.LookupGroupId(strconv.FormatUint(gid, 10))
			if err != nil {
				return 1, err.Error()
			}

			// invoke adduser
			exitCode, result = runCmdWithOutput(
				[]string{
					"/usr/sbin/adduser",
					data.Username,
					group.Name,
				},
				"root", "", nil, 60,
			)
			if exitCode != 0 {
				return exitCode, result
			}
		}
	} else if utils.PlatformLike == "rhel" {
		exitCode, result = runCmdWithOutput(
			[]string{
				"/usr/sbin/useradd",
				"--home-dir", data.HomeDirectory,
				"--shell", data.Shell,
				"--uid", strconv.FormatUint(data.UID, 10),
				"--gid", strconv.FormatUint(data.GID, 10),
				"--groups", utils.JoinUint64s(cr.data.Groups),
				"--comment", data.Comment,
				data.Username,
			},
			"root", "", nil, 60,
		)
		if exitCode != 0 {
			return exitCode, result
		}
	} else {
		return 1, "Not implemented 'adduser' command for this platform."
	}

	// Set default permission for home directory if not provided
	if data.HomeDirectoryPermission == "" {
		data.HomeDirectoryPermission = "700"
	}

	exitCode, result = runCmdWithOutput(
		[]string{
			"chmod", data.HomeDirectoryPermission, data.HomeDirectory,
		},
		"root", "", nil, 60,
	)
	if exitCode != 0 {
		return exitCode, result
	}

	cr.sync([]string{"groups", "users"})
	return 0, "Successfully added new user."
}

func (cr *CommandRunner) addGroup() (exitCode int, result string) {
	data := addGroupData{
		Groupname: cr.data.Groupname,
		GID:       cr.data.GID,
	}

	err := cr.validateData(data)
	if err != nil {
		return 1, fmt.Sprintf("addgroup: Not enough information. %s", err)
	}

	if utils.PlatformLike == "debian" {
		exitCode, result = runCmdWithOutput(
			[]string{
				"/usr/sbin/addgroup",
				"--gid", strconv.FormatUint(data.GID, 10),
				data.Groupname,
			},
			"root", "", nil, 60,
		)
		if exitCode != 0 {
			return exitCode, result
		}
	} else if utils.PlatformLike == "rhel" {
		exitCode, result = runCmdWithOutput(
			[]string{
				"/usr/sbin/groupadd",
				"--gid", strconv.FormatUint(data.GID, 10),
				data.Groupname,
			},
			"root", "", nil, 60,
		)
		if exitCode != 0 {
			return exitCode, result
		}
	} else {
		return 1, "Not implemented 'addgroup' command for this platform."
	}

	cr.sync([]string{"groups", "users"})
	return 0, "Successfully added new group."
}

func (cr *CommandRunner) delUser() (exitCode int, result string) {
	data := deleteUserData{
		Username: cr.data.Username,
	}

	err := cr.validateData(data)
	if err != nil {
		return 1, fmt.Sprintf("deluser: Not enough information. %s", err)
	}

	if utils.PlatformLike == "debian" {
		exitCode, result = runCmdWithOutput(
			[]string{
				"/usr/sbin/deluser",
				data.Username,
			},
			"root", "", nil, 60,
		)
		if exitCode != 0 {
			return exitCode, result
		}
	} else if utils.PlatformLike == "rhel" {
		exitCode, result = runCmdWithOutput(
			[]string{
				"/usr/sbin/userdel",
				data.Username,
			},
			"root", "", nil, 60,
		)
		if exitCode != 0 {
			return exitCode, result
		}
	} else {
		return 1, "Not implemented 'deluser' command for this platform."
	}

	cr.sync([]string{"groups", "users"})
	return 0, "Successfully deleted the user."
}

func (cr *CommandRunner) delGroup() (exitCode int, result string) {
	data := deleteGroupData{
		Groupname: cr.data.Groupname,
	}

	err := cr.validateData(data)
	if err != nil {
		return 1, fmt.Sprintf("delgroup: Not enough information. %s", err)
	}

	if utils.PlatformLike == "debian" {
		exitCode, result = runCmdWithOutput(
			[]string{
				"/usr/sbin/delgroup",
				data.Groupname,
			},
			"root", "", nil, 60,
		)
		if exitCode != 0 {
			return exitCode, result
		}
	} else if utils.PlatformLike == "rhel" {
		exitCode, result = runCmdWithOutput(
			[]string{
				"/usr/sbin/groupdel",
				data.Groupname,
			},
			"root", "", nil, 60,
		)
		if exitCode != 0 {
			return exitCode, result
		}
	} else {
		return 1, "Not implemented 'delgroup' command for this platform."
	}

	cr.sync([]string{"groups", "users"})
	return 0, "Successfully deleted the group."
}

func (cr *CommandRunner) modUser() (exitCode int, result string) {
	data := modUserData{
		Username: cr.data.Username,
		Comment:  cr.data.Comment,
	}

	err := cr.validateData(data)
	if err != nil {
		return 1, fmt.Sprintf("moduser: Not enough information. %s", err)
	}

	if utils.PlatformLike == "debian" || utils.PlatformLike == "rhel" {
		exitCode, result = runCmdWithOutput(
			[]string{
				"/usr/sbin/usermod",
				"--comment", data.Comment,
				"-G", utils.JoinUint64s(cr.data.Groups),
				data.Username,
			},
			"root", "", nil, 60,
		)
		if exitCode != 0 {
			return exitCode, result
		}
	} else {
		return 1, "Not implemented 'moduser' command for this platform."
	}

	cr.sync([]string{"groups", "users"})
	return 0, "Successfully modified user information."
}

func (cr *CommandRunner) runFileUpload(fileName string) (exitCode int, result string) {
	log.Debug().Msgf("Uploading file to %s. (username: %s, groupname: %s)", fileName, cr.data.Username, cr.data.Groupname)

	sysProcAttr, err := demote(cr.data.Username, cr.data.Groupname)
	if err != nil {
		log.Error().Err(err).Msg("Failed to demote user.")
		return 1, err.Error()
	}

	if len(cr.data.Paths) == 0 {
		return 1, "No paths provided"
	}

	paths, bulk, recursive, err := parsePaths(cr.data.Paths)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse paths")
		return 1, err.Error()
	}

	name, err := makeArchive(paths, bulk, recursive, sysProcAttr)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create archive")
		return 1, err.Error()
	}

	if bulk || recursive {
		defer func() { _ = os.Remove(name) }()
	}

	cmd := exec.Command("cat", name)
	cmd.SysProcAttr = sysProcAttr

	output, err := cmd.Output()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to cat file: %s", output)
		return 1, err.Error()
	}

	requestBody, contentType, err := createMultipartBody(output, filepath.Base(name), cr.data.UseBlob, recursive)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to make request body")
		return 1, err.Error()
	}

	_, statusCode, err := cr.fileUpload(requestBody, contentType)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to upload file: %s", fileName)
		return 1, err.Error()
	}

	if statusCode == http.StatusOK {
		return 0, fmt.Sprintf("Successfully uploaded %s.", fileName)
	}

	return 1, "You do not have permission to read on the directory. or directory does not exist"
}

func (cr *CommandRunner) fileUpload(body bytes.Buffer, contentType string) ([]byte, int, error) {
	if cr.data.UseBlob {
		return utils.Put(cr.data.Content, body, 0)
	}

	return cr.wsClient.apiSession.MultipartRequest(cr.data.Content, body, contentType, fileUploadTimeout)
}

func (cr *CommandRunner) runFileDownload(fileName string) (exitCode int, result string) {
	log.Debug().Msgf("Downloading file to %s. (username: %s, groupname: %s)", fileName, cr.data.Username, cr.data.Groupname)

	var code int
	var message string
	sysProcAttr, err := demote(cr.data.Username, cr.data.Groupname)
	if err != nil {
		log.Error().Err(err).Msg("Failed to demote user.")
		return 1, err.Error()
	}

	if len(cr.data.Files) == 0 {
		code, message = fileDownload(cr.data, sysProcAttr)
		statFileTransfer(code, UPLOAD, message, cr.data)
	} else {
		for _, file := range cr.data.Files {
			cmdData := CommandData{
				Username:       file.Username,
				Groupname:      file.Groupname,
				Type:           file.Type,
				Content:        file.Content,
				Path:           file.Path,
				AllowOverwrite: file.AllowOverwrite,
				AllowUnzip:     file.AllowUnzip,
				URL:            file.URL,
			}
			code, message = fileDownload(cmdData, sysProcAttr)
			statFileTransfer(code, UPLOAD, message, cmdData)
		}
	}

	if code != 0 {
		return code, message
	}

	return 0, fmt.Sprintf("Successfully downloaded %s.", fileName)
}

func (cr *CommandRunner) validateData(data interface{}) error {
	err := cr.validator.Struct(data)
	if err != nil {
		return err
	}
	return nil
}

func (cr *CommandRunner) openFtp(data openFtpData) error {
	sysProcAttr, err := demoteFtp(data.Username, data.Groupname)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get demote permission")

		return fmt.Errorf("openftp: Failed to get demoted permission. %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to get executable path")

		return fmt.Errorf("openftp: Failed to get executable path. %w", err)
	}

	cmd := exec.Command(
		executable,
		"ftp",
		data.URL,
		config.GlobalSettings.ServerURL,
		data.HomeDirectory,
	)
	cmd.SysProcAttr = sysProcAttr
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err = cmd.Start(); err != nil {
		log.Debug().Err(err).Msg("Failed to start ftp worker process")

		return fmt.Errorf("openftp: Failed to start ftp worker process. %w", err)
	}

	return nil
}

func (cr *CommandRunner) iptables() (exitCode int, result string) {
	data := iptablesCommandData{
		Method: cr.iptablesData.Method,
		Chain:  cr.iptablesData.Chain,
		Protocol: cr.iptablesData.Protocol,
		PortStart: cr.iptablesData.PortStart,
		PortEnd: cr.iptablesData.PortEnd,
		DPorts: cr.iptablesData.DPorts,
		ICMPType: cr.iptablesData.ICMPType,
		Source: cr.iptablesData.Source,
		Target: cr.iptablesData.Target,
		Description: cr.iptablesData.Description,
		Priority: cr.iptablesData.Priority,
	}

	err := cr.validateData(data)
	if err != nil {
		return 1, fmt.Sprintf("iptables: Not enough information. %s", err)
	}

	args := []string{
		"iptables",
		data.Method, data.Chain,
		"-p", data.Protocol,
		"-s", data.Source,
		"-j", data.Target,
	}

	if data.PortStart != 0 {
		args = append(args, "--dport", strconv.Itoa(data.PortStart))
	}
	if data.PortEnd != 0 && data.PortStart != 0 {
		args = append(args, "--dport", strconv.Itoa(data.PortEnd))
	}
	

	exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)

	if exitCode != 0 {
		return exitCode, result
	}

	return 0, "Successfully added new iptables rule."
}

func getFileData(data CommandData) ([]byte, error) {
	var content []byte
	switch data.Type {
	case "url":
		parsedRequestURL, err := url.Parse(data.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to parse URL '%s': %w", data.Content, err)
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

		client := http.Client{}

		tlsConfig := &tls.Config{}
		if config.GlobalSettings.CaCert != "" {
			caCertPool := x509.NewCertPool()
			caCert, err := os.ReadFile(config.GlobalSettings.CaCert)
			if err != nil {
				log.Error().Err(err).Msg("Failed to read CA certificate.")
			}
			caCertPool.AppendCertsFromPEM(caCert)
			tlsConfig.RootCAs = caCertPool
		}

		tlsConfig.InsecureSkipVerify = !config.GlobalSettings.SSLVerify
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to download content from URL: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if (resp.StatusCode / 100) != 2 {
			log.Error().Msgf("Failed to download content from URL: %d %s", resp.StatusCode, parsedRequestURL)
			return nil, errors.New("downloading content failed")
		}
		content, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}
	case "text":
		content = []byte(data.Content)
	case "base64":
		var err error
		content, err = base64.StdEncoding.DecodeString(data.Content)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 content: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown file type: %s", data.Type)
	}

	if content == nil {
		return nil, errors.New("content is nil")
	}

	return content, nil
}

func parsePaths(pathList []string) (parsedPaths []string, isBulk bool, isRecursive bool, err error) {
	paths := make([]string, len(pathList))
	for i, path := range pathList {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil, false, false, err
		}
		paths[i] = absPath
	}

	isBulk = len(pathList) > 1
	isRecursive = false

	if !isBulk {
		fileInfo, err := os.Stat(paths[0])
		if err != nil {
			return nil, false, false, err
		}
		isRecursive = fileInfo.IsDir()
	}

	return paths, isBulk, isRecursive, nil
}

func makeArchive(paths []string, bulk, recursive bool, sysProcAttr *syscall.SysProcAttr) (string, error) {
	var archiveName string
	var cmd *exec.Cmd
	path := paths[0]

	if bulk {
		archiveName = filepath.Dir(path) + "/" + uuid.New().String() + ".zip"
		dirPath := filepath.Dir(path)
		basePaths := make([]string, len(paths))
		for i, path := range paths {
			basePaths[i] = filepath.Base(path)
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

func createMultipartBody(output []byte, filePath string, useBlob, isRecursive bool) (bytes.Buffer, string, error) {
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

func fileDownload(data CommandData, sysProcAttr *syscall.SysProcAttr) (exitCode int, result string) {
	var cmd *exec.Cmd
	content, err := getFileData(data)
	if err != nil {
		return 1, err.Error()
	}

	if !data.AllowOverwrite && isFileExist(data.Path) {
		return 1, fmt.Sprintf("%s already exists.", data.Path)
	}

	isZip := isZipFile(content, filepath.Ext(data.Path))
	if isZip && data.AllowUnzip {
		escapePath := utils.Quote(data.Path)
		escapeDirPath := utils.Quote(filepath.Dir(data.Path))
		command := fmt.Sprintf("tee %s > /dev/null && unzip -n %s -d %s; rm %s",
			escapePath,
			escapePath,
			escapeDirPath,
			escapePath)
		cmd = exec.Command("sh", "-c", command)
	} else {
		cmd = exec.Command("sh", "-c", fmt.Sprintf("tee %s > /dev/null", utils.Quote(data.Path)))
	}

	cmd.SysProcAttr = sysProcAttr
	cmd.Stdin = bytes.NewReader(content)

	output, err := cmd.Output()
	if err != nil {
		log.Error().Err(err).Msgf("Failed to write file: %s", output)
		return 1, "You do not have permission to read on the directory. or directory does not exist"
	}

	return 0, fmt.Sprintf("Successfully downloaded %s.", data.Path)
}

func isZipFile(content []byte, ext string) bool {
	if _, found := nonZipExt[ext]; found {
		return false
	}

	_, err := zip.NewReader(bytes.NewReader(content), int64(len(content)))

	return err == nil
}

func isFileExist(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func statFileTransfer(code int, transferType transferType, message string, data CommandData) {
	statURL := fmt.Sprint(data.URL + "stat/")
	isSuccess := code == 0

	payload := &commandStat{
		Success: isSuccess,
		Message: message,
		Type:    transferType,
	}
	scheduler.Rqueue.Post(statURL, payload, 10, time.Time{})
}
