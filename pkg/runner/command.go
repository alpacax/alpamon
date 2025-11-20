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

	"github.com/alpacax/alpamon/pkg/config"
	"github.com/alpacax/alpamon/pkg/scheduler"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/alpacax/alpamon/pkg/version"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"gopkg.in/go-playground/validator.v9"
)

const (
	fileUploadTimeout = 60 * 10
)

func init() {
	// Inject runCmdWithOutput function into utils.firewall package
	utils.SetFirewallCommandExecutor(runCmdWithOutput)
}

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

	if cr.command.ID != "" {
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
	case "firewall":
		if utils.IsFirewallDisabled() {
			log.Warn().Msg("Firewall command ignored - firewall functionality is temporarily disabled")
			return 0, "Firewall functionality is temporarily disabled"
		}
		backendInfo := utils.DetectFirewallBackend(true)
		if backendInfo.Type == "ufw" || backendInfo.Type == "firewalld" {
			return 1, fmt.Sprintf("Alpacon firewall management is disabled because %s is active. Please use %s to manage firewall rules.", backendInfo.Type, backendInfo.Type)
		}
		return cr.firewall()
	case "firewall-rollback":
		if utils.IsFirewallDisabled() {
			log.Warn().Msg("Firewall rollback command ignored - firewall functionality is temporarily disabled")
			return 0, "Firewall functionality is temporarily disabled"
		}
		backendInfo := utils.DetectFirewallBackend(true)
		if backendInfo.Type == "ufw" || backendInfo.Type == "firewalld" {
			return 1, fmt.Sprintf("Alpacon firewall management is disabled because %s is active. Please use %s to manage firewall rules.", backendInfo.Type, backendInfo.Type)
		}
		return cr.firewallRollback()
	case "firewall-reorder-chains":
		if utils.IsFirewallDisabled() {
			log.Warn().Msg("Firewall reorder-chains command ignored - firewall functionality is temporarily disabled")
			return 0, "Firewall functionality is temporarily disabled"
		}
		backendInfo := utils.DetectFirewallBackend(true)
		if backendInfo.Type == "ufw" || backendInfo.Type == "firewalld" {
			return 1, fmt.Sprintf("Alpacon firewall management is disabled because %s is active. Please use %s to manage firewall rules.", backendInfo.Type, backendInfo.Type)
		}
		return cr.firewallReorderChains()
	case "firewall-reorder-rules":
		if utils.IsFirewallDisabled() {
			log.Warn().Msg("Firewall reorder-rules command ignored - firewall functionality is temporarily disabled")
			return 0, "Firewall functionality is temporarily disabled"
		}
		backendInfo := utils.DetectFirewallBackend(true)
		if backendInfo.Type == "ufw" || backendInfo.Type == "firewalld" {
			return 1, fmt.Sprintf("Alpacon firewall management is disabled because %s is active. Please use %s to manage firewall rules.", backendInfo.Type, backendInfo.Type)
		}
		return cr.firewallReorderRules()
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
		Username:           cr.data.Username,
		PurgeHomeDirectory: cr.data.PurgeHomeDirectory,
	}

	err := cr.validateData(data)
	if err != nil {
		return 1, fmt.Sprintf("deluser: Not enough information. %s", err)
	}

	cmd := "/usr/sbin/userdel"
	args := []string{}

	switch utils.PlatformLike {
	case "debian":
		cmd = "/usr/sbin/deluser"
		if data.PurgeHomeDirectory {
			args = append(args, "--remove-home")
		}
	case "rhel":
		if data.PurgeHomeDirectory {
			args = append(args, "--remove")
		}
	default:
		return 1, "Not implemented 'deluser' command for this platform."
	}

	if !data.PurgeHomeDirectory {
		homeDir := fmt.Sprintf("/home/%s", data.Username)
		timestamp := time.Now().UTC().Format(time.RFC3339)
		backupDir := fmt.Sprintf("/home/deleted_users/%s_%s", data.Username, timestamp)

		err = os.MkdirAll("/home/deleted_users", 0700)
		if err != nil {
			return 1, fmt.Sprintf("Failed to create backup directory: %v", err)
		}

		_, err = os.Stat(homeDir)
		if err != nil {
			return 1, fmt.Sprintf("%s not exist: %v", homeDir, err)
		}

		err = os.Rename(homeDir, backupDir)
		if err != nil {
			return 1, fmt.Sprintf("Failed to move home directory: %v", err)
		}

		err = utils.ChownRecursive(backupDir, 0, 0)
		if err != nil {
			return 1, fmt.Sprintf("Failed to chown backup directory: %v", err)
		}
	}

	args = append(args, data.Username)
	cmdString := append([]string{cmd}, args...)

	exitCode, result = runCmdWithOutput(
		cmdString,
		"root", "", nil, 60,
	)
	if exitCode != 0 {
		return exitCode, result
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
		Username:   cr.data.Username,
		Groupnames: cr.data.Groupnames,
		Comment:    cr.data.Comment,
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
				"-G", strings.Join(data.Groupnames, ","),
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

	sysProcAttr, homeDirectory, err := demoteFtp(cr.data.Username, cr.data.Groupname)
	if err != nil {
		log.Error().Err(err).Msg("Failed to demote user.")
		return 1, err.Error()
	}

	if len(cr.data.Paths) == 0 {
		return 1, "No paths provided"
	}

	paths, bulk, recursive, err := parsePaths(homeDirectory, cr.data.Paths)
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
	sysProcAttr, homeDirectory, err := demoteFtp(data.Username, data.Groupname)
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
		homeDirectory,
	)
	cmd.SysProcAttr = sysProcAttr
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		log.Debug().Err(err).Msg("Failed to start ftp worker process")

		return fmt.Errorf("openftp: Failed to start ftp worker process. %w", err)
	}

	go func() { _ = cmd.Wait() }()

	return nil
}

func (cr *CommandRunner) firewall() (exitCode int, result string) {
	log.Info().Msgf("Firewall operation: %s, Backend: %s", cr.data.Operation, cr.data.Backend)

	// Validate required fields based on operation
	if cr.data.Operation == "" {
		return 1, "firewall: operation is required"
	}

	// Detect backend if not explicitly provided
	if cr.data.Backend == "" {
		backendInfo := utils.DetectFirewallBackend(true)
		cr.data.Backend = backendInfo.Type
		log.Debug().Msgf("Auto-detected firewall backend: %s", cr.data.Backend)
	}

	// Log the backend being used
	if cr.data.Backend == "firewalld" || cr.data.Backend == "ufw" {
		log.Debug().Msgf("Using high-level firewall backend: %s", cr.data.Backend)
	} else {
		log.Debug().Msgf("Using low-level firewall backend: %s", cr.data.Backend)
	}

	// Route to appropriate operation handler based on backend
	switch cr.data.Backend {
	case "firewalld":
		return cr.handleFirewalldOperation()
	case "ufw":
		return cr.handleUFWOperation()
	case "nftables", "iptables", "":
		// Use existing iptables/nftables handlers
		switch cr.data.Operation {
		case "batch":
			return cr.handleBatchOperation()
		case "flush":
			return cr.handleFlushOperation()
		case "delete":
			return cr.handleDeleteOperation()
		case "add":
			return cr.handleAddOperation()
		case "update":
			return cr.handleUpdateOperation()
		case "update-comment":
			return cr.handleUpdateCommentOperation()
		default:
			return 1, fmt.Sprintf("firewall: Unknown operation '%s'. Supported: batch, flush, delete, add, update, update-comment", cr.data.Operation)
		}
	default:
		return 1, fmt.Sprintf("firewall: Unsupported backend '%s'. Supported: iptables, nftables, firewalld, ufw", cr.data.Backend)
	}
}

// handleBatchOperation handles batch application of firewall rules
func (cr *CommandRunner) handleBatchOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall batch operation - RuleCount: %d", len(cr.data.Rules))

	if len(cr.data.Rules) == 0 {
		// Empty batch is considered successful (no-op)
		log.Warn().Msg("Firewall batch operation with no rules - treating as no-op")
		return 0, `{"success": true, "applied_rules": 0, "failed_rules": [], "rolled_back": false, "rollback_reason": null, "message": "No rules to apply"}`
	}

	// Use the common batch apply logic with rollback on failure
	appliedRules, failedRules, rolledBack, rollbackReason := cr.applyRulesBatchWithFlush()

	// Prepare response in batch format
	if rolledBack {
		return 1, fmt.Sprintf(`{"success": false, "error": "Failed to apply rules", "applied_rules": %d, "failed_rules": %d, "rolled_back": true, "rollback_reason": "%s"}`,
			appliedRules, len(failedRules), rollbackReason)
	}

	return 0, fmt.Sprintf(`{"success": true, "applied_rules": %d, "failed_rules": [], "rolled_back": false, "rollback_reason": null}`, appliedRules)
}

// handleFlushOperation handles flushing firewall chains
// Uses existing rollback functions to perform flush
// Supports both old format (chain name only) and new format (family table chain)
func (cr *CommandRunner) handleFlushOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall flush operation - Chain: %s", cr.data.Chain)

	// Validate chain is provided
	if cr.data.Chain == "" {
		return 1, `{"success": false, "error": "Chain name is required for flush operation"}`
	}

	// Check firewall backend
	nftablesInstalled, iptablesInstalled, err := utils.CheckFirewallTool()
	if err != nil {
		log.Error().Err(err).Msg("Failed to check firewall tools")
		return 1, fmt.Sprintf(`{"success": false, "error": "Failed to check firewall tools: %v"}`, err)
	}

	// Create backup before flushing
	backup, err := utils.BackupFirewallRules()
	if err != nil {
		log.Error().Err(err).Msg("Failed to create backup before flush")
		return 1, fmt.Sprintf(`{"success": false, "error": "Failed to create backup: %v"}`, err)
	}

	var flushExitCode int
	var flushResult string

	if nftablesInstalled {
		// For nftables, chain can be:
		// 1. Old format: just table name (e.g., "alpacon-sg-123")
		// 2. New format: "family table chain" (e.g., "inet filter alpacon-sg-123_input")
		// performNftablesRollback will handle both formats
		flushExitCode, flushResult = cr.performNftablesRollback(cr.data.Chain, "flush")
	} else if iptablesInstalled {
		// For iptables, use the chain name directly
		flushExitCode, flushResult = cr.performIptablesRollback(cr.data.Chain, "flush")
	} else {
		return 1, `{"success": false, "error": "No firewall backend available"}`
	}

	// If flush failed, restore backup
	if flushExitCode != 0 {
		log.Error().Msgf("Flush operation failed: %s", flushResult)
		if restoreErr := utils.RestoreFirewallRules(backup); restoreErr != nil {
			log.Error().Err(restoreErr).Msg("Failed to restore backup after flush failure")
			return flushExitCode, fmt.Sprintf(`{"success": false, "error": "%s", "backup_restore_failed": true}`, flushResult)
		}
		return flushExitCode, fmt.Sprintf(`{"success": false, "error": "%s", "backup_restored": true}`, flushResult)
	}

	log.Info().Msg("Successfully completed flush operation")
	return 0, fmt.Sprintf(`{"success": true, "message": "%s"}`, flushResult)
}

// handleDeleteOperation handles deleting a specific firewall rule by rule_id
func (cr *CommandRunner) handleDeleteOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall delete operation - Chain: %s, RuleID: %s", cr.data.Chain, cr.data.RuleID)

	// Validate required fields
	if cr.data.RuleID == "" {
		return 1, "firewall delete: rule_id is required for delete operation"
	}

	// Create backup before deleting
	backup, err := utils.BackupFirewallRules()
	if err != nil {
		return 1, fmt.Sprintf("firewall delete: Failed to create backup: %v", err)
	}

	nftablesInstalled, iptablesInstalled, err := utils.CheckFirewallTool()
	if err != nil {
		return 1, fmt.Sprintf("firewall delete: Failed to check firewall tools. %s", err)
	}

	var deleteExitCode int
	var deleteResult string

	// cr.data.Chain now contains the complete chain name (e.g., "alpacon-web_input")
	if nftablesInstalled {
		deleteExitCode, deleteResult = cr.deleteNftablesRuleByID(cr.data.Chain, cr.data.RuleID)
	} else if iptablesInstalled {
		deleteExitCode, deleteResult = cr.deleteIptablesRuleByID(cr.data.Chain, cr.data.RuleID)
	} else {
		return 1, "firewall delete: No firewall management tool installed"
	}

	// If deletion failed, restore backup
	if deleteExitCode != 0 {
		log.Error().Msgf("Failed to delete rule, restoring backup: %s", deleteResult)
		if restoreErr := utils.RestoreFirewallRules(backup); restoreErr != nil {
			log.Error().Err(restoreErr).Msg("Failed to restore backup after delete failure")
			return deleteExitCode, fmt.Sprintf("firewall delete: Failed and restore failed: %s", deleteResult)
		}
		return deleteExitCode, fmt.Sprintf("firewall delete: Failed, backup restored: %s", deleteResult)
	}

	return deleteExitCode, deleteResult
}

// handleAddOperation handles adding a single firewall rule
func (cr *CommandRunner) handleAddOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall add operation - Chain: %s", cr.data.Chain)

	// Log all received data for debugging
	log.Debug().Msgf("Received firewall add data: Method=%s, Chain=%s, Protocol=%s, PortStart=%d, PortEnd=%d, DPorts=%v, ICMPType=%s, Source=%s, Destination=%s, Target=%s, Priority=%d, RuleID=%s, RuleType=%s",
		cr.data.Method, cr.data.Chain, cr.data.Protocol,
		cr.data.PortStart, cr.data.PortEnd, cr.data.DPorts, cr.data.ICMPType,
		cr.data.Source, cr.data.Destination, cr.data.Target, cr.data.Priority,
		cr.data.RuleID, cr.data.RuleType)

	// Validate required fields for rule addition
	if err := cr.validateFirewallRuleData(); err != nil {
		return 1, fmt.Sprintf("firewall add: Validation failed. %s", err)
	}

	return cr.executeSingleFirewallRule()
}

// handleUpdateOperation handles updating a firewall rule
func (cr *CommandRunner) handleUpdateOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall update operation - Chain: %s, OldRuleID: %s, NewRuleID: %s",
		cr.data.Chain, cr.data.OldRuleID, cr.data.RuleID)

	// Validate required fields for rule update
	if err := cr.validateFirewallRuleData(); err != nil {
		return 1, fmt.Sprintf("firewall update: Validation failed. %s", err)
	}

	// For update operation: delete old rule first, then add new one with new ID
	// old_rule_id: the rule to delete
	// rule_id: the new rule to add
	// TODO: Consider changing order to add-then-delete for better safety

	if cr.data.OldRuleID == "" {
		return 1, "firewall update: old_rule_id is required for update operation"
	}

	// Create backup before updating
	backup, err := utils.BackupFirewallRules()
	if err != nil {
		return 1, fmt.Sprintf("firewall update: Failed to create backup: %v", err)
	}

	// Step 1: Check firewall tools
	nftablesInstalled, iptablesInstalled, err := utils.CheckFirewallTool()
	if err != nil {
		return 1, fmt.Sprintf("firewall update: Failed to check firewall tools. %s", err)
	}

	// Step 2: Delete the old rule using old_rule_id
	// cr.data.Chain now contains the complete chain name (e.g., "alpacon-web_input")
	var deleteExitCode int
	var deleteResult string

	if nftablesInstalled {
		deleteExitCode, deleteResult = cr.deleteNftablesRuleByID(cr.data.Chain, cr.data.OldRuleID)
	} else if iptablesInstalled {
		deleteExitCode, deleteResult = cr.deleteIptablesRuleByID(cr.data.Chain, cr.data.OldRuleID)
	} else {
		return 1, "firewall update: No firewall tool available"
	}

	if deleteExitCode != 0 {
		// If deletion fails, restore backup
		log.Error().Msgf("Failed to delete old rule during update, restoring backup: %s", deleteResult)
		if restoreErr := utils.RestoreFirewallRules(backup); restoreErr != nil {
			log.Error().Err(restoreErr).Msg("Failed to restore backup after delete failure")
			return deleteExitCode, fmt.Sprintf("firewall update: Failed to delete old rule and restore failed: %s", deleteResult)
		}
		return deleteExitCode, fmt.Sprintf("firewall update: Failed to delete old rule, backup restored: %s", deleteResult)
	}

	// Step 3: Add the new rule with new rule_id (stored in cr.data.RuleID)
	addExitCode, addResult := cr.executeSingleFirewallRule()

	if addExitCode != 0 {
		// Adding new rule failed, restore backup (old rule was deleted)
		log.Error().Msgf("Failed to add new rule during update, restoring backup: %s", addResult)
		if restoreErr := utils.RestoreFirewallRules(backup); restoreErr != nil {
			log.Error().Err(restoreErr).Msg("Failed to restore backup after add failure")
			return addExitCode, fmt.Sprintf("firewall update: Failed to add new rule and restore failed: %s", addResult)
		}
		return addExitCode, fmt.Sprintf("firewall update: Failed to add new rule, backup restored: %s", addResult)
	}

	log.Info().Msgf("Successfully updated firewall rule: deleted %s, added %s", cr.data.OldRuleID, cr.data.RuleID)
	return 0, fmt.Sprintf("Successfully updated rule: deleted %s, added %s", cr.data.OldRuleID, cr.data.RuleID)
}

// handleUpdateCommentOperation handles updating comments for multiple firewall rules
func (cr *CommandRunner) handleUpdateCommentOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall update-comment operation - RuleCount: %d", len(cr.data.Rules))

	if len(cr.data.Rules) == 0 {
		return 0, `{"success": true, "updated_rules": 0, "failed_rules": [], "message": "No rules to update"}`
	}

	// Check firewall backend
	nftablesInstalled, iptablesInstalled, err := utils.CheckFirewallTool()
	if err != nil {
		return 1, fmt.Sprintf("firewall update-comment: Failed to check firewall tools: %v", err)
	}

	if !nftablesInstalled && !iptablesInstalled {
		return 1, "firewall update-comment: No firewall backend available"
	}

	updatedCount := 0
	var failedRules []map[string]string

	// Process each rule
	for _, ruleData := range cr.data.Rules {
		ruleID, _ := ruleData["rule_id"].(string)
		ruleType, _ := ruleData["rule_type"].(string)
		description, _ := ruleData["description"].(string)
		table, _ := ruleData["table"].(string)
		family, _ := ruleData["family"].(string)
		chain, _ := ruleData["chain"].(string)

		// Check required fields only
		if ruleID == "" || chain == "" || ruleType == "" {
			log.Warn().Msgf("Skipping rule with missing required fields - rule_id: %s, chain: %s, rule_type: %s", ruleID, chain, ruleType)
			failedRules = append(failedRules, map[string]string{
				"rule_id": ruleID,
				"error":   "missing rule_id, chain, or rule_type",
			})
			continue
		}

		// Build new comment with metadata
		newComment := utils.BuildFirewallComment(description, ruleID, ruleType)

		// Convert rule data to FirewallRuleSync
		rule := cr.convertToFirewallRuleSync(ruleData)

		// Update comment based on backend
		var success bool
		if nftablesInstalled {
			// For nftables, use family and table separately
			// Default to "inet" and "filter" if not provided
			if table == "" {
				table = "filter"
			}
			if family == "" {
				family = "inet"
			}
			success = utils.RecreateNftablesRuleWithComment(family, table, rule, newComment)
		} else if iptablesInstalled {
			// For iptables, use table and chain separately
			// Default to "filter" if not provided
			if table == "" {
				table = "filter"
			}
			success = utils.RecreateIptablesRuleWithComment(table, chain, rule, newComment)
		}

		if success {
			updatedCount++
			log.Debug().Msgf("Updated comment for rule %s", ruleID)
		} else {
			log.Warn().Msgf("Failed to update comment for rule %s", ruleID)
			failedRules = append(failedRules, map[string]string{
				"rule_id": ruleID,
				"error":   "failed to recreate rule with updated comment",
			})
		}
	}

	if len(failedRules) > 0 {
		return 1, fmt.Sprintf(`{"success": false, "updated_rules": %d, "failed_rules": %d}`, updatedCount, len(failedRules))
	}

	return 0, fmt.Sprintf(`{"success": true, "updated_rules": %d, "failed_rules": []}`, updatedCount)
}

// convertToFirewallRuleSync converts rule data map to FirewallRuleSync struct
func (cr *CommandRunner) convertToFirewallRuleSync(ruleData map[string]interface{}) *utils.FirewallRuleSync {
	rule := &utils.FirewallRuleSync{}

	if protocol, ok := ruleData["protocol"].(string); ok {
		rule.Protocol = protocol
	}

	if source, ok := ruleData["source"].(string); ok {
		rule.SourceCIDR = source
	}

	if destination, ok := ruleData["destination"].(string); ok {
		rule.DestinationCIDR = destination
	}

	if target, ok := ruleData["target"].(string); ok {
		rule.Target = target
	}

	if chain, ok := ruleData["chain"].(string); ok {
		rule.Chain = chain
	}

	if ruleID, ok := ruleData["rule_id"].(string); ok {
		rule.RuleID = ruleID
	}

	if ruleType, ok := ruleData["rule_type"].(string); ok {
		rule.RuleType = ruleType
	}

	if table, ok := ruleData["table"].(string); ok {
		rule.Table = table
	}

	if family, ok := ruleData["family"].(string); ok {
		rule.Family = family
	}

	if priority, ok := ruleData["priority"].(float64); ok {
		rule.Priority = int(priority)
	}

	// Handle ports
	if dports, ok := ruleData["dports"].([]interface{}); ok && len(dports) > 0 {
		var ports []string
		for _, p := range dports {
			if port, ok := p.(float64); ok {
				ports = append(ports, fmt.Sprintf("%.0f", port))
			}
		}
		if len(ports) > 0 {
			rule.Dports = strings.Join(ports, ",")
		}
	} else if portStart, ok := ruleData["port_start"].(float64); ok {
		ps := int(portStart)
		rule.PortStart = &ps

		if portEnd, ok := ruleData["port_end"].(float64); ok {
			pe := int(portEnd)
			rule.PortEnd = &pe
		}
	}

	// Handle ICMP type
	if icmpType, ok := ruleData["icmp_type"].(float64); ok {
		it := int(icmpType)
		rule.ICMPType = &it
	}

	return rule
}

// validateFirewallRuleData performs validation for single rule operations
func (cr *CommandRunner) validateFirewallRuleData() error {
	// Set default rule type if not provided
	if cr.data.RuleType == "" {
		cr.data.RuleType = "alpacon"
	}

	// Generate rule ID if not provided
	if cr.data.RuleID == "" {
		cr.data.RuleID = uuid.New().String()
	}

	data := firewallData{
		Method:      cr.data.Method,
		Chain:       cr.data.Chain,
		Protocol:    cr.data.Protocol,
		PortStart:   cr.data.PortStart,
		PortEnd:     cr.data.PortEnd,
		DPorts:      cr.data.DPorts,
		ICMPType:    cr.data.ICMPType,
		Source:      cr.data.Source,
		Destination: cr.data.Destination,
		Target:      cr.data.Target,
		Description: cr.data.Description,
		Priority:    cr.data.Priority,
		RuleType:    cr.data.RuleType,
		RuleID:      cr.data.RuleID,
		Operation:   cr.data.Operation,
	}

	return cr.validateFirewallData(data)
}

// executeSingleFirewallRule executes a single firewall rule operation
func (cr *CommandRunner) executeSingleFirewallRule() (exitCode int, result string) {
	nftablesInstalled, iptablesInstalled, err := utils.CheckFirewallTool()
	if err != nil {
		return 1, fmt.Sprintf("firewall: Failed to check firewall tools. %s", err)
	}

	if nftablesInstalled {
		return cr.executeNftablesRule()
	} else if iptablesInstalled {
		return cr.executeIptablesRule()
	}

	return 1, "firewall: No firewall management tool installed"
}

// executeNftablesRule executes nftables rule
func (cr *CommandRunner) executeNftablesRule() (exitCode int, result string) {
	log.Info().Msg("Using nftables for firewall management.")

	// Determine family (default to inet if not specified)
	family := cr.data.Family
	if family == "" {
		family = "inet"
	}
	log.Info().Msgf("Using nftables family: %s", family)

	// Get table name (default to "filter" if not specified)
	tableName := cr.data.Table
	if tableName == "" {
		tableName = "filter"
	}

	// Create table dynamically
	tableCmdArgs := []string{"nft", "add", "table", family, tableName}
	_, _ = runCmdWithOutput(tableCmdArgs, "root", "", nil, 60)

	// Create chain in the new table
	// cr.data.Chain now contains the complete chain name (e.g., "alpacon-web_input")
	chainName := cr.data.Chain
	chainCmdArgs := []string{"nft", "add", "chain", family, tableName, chainName}

	// Determine hook type from chain name suffix
	if strings.HasSuffix(strings.ToLower(chainName), "_input") {
		chainCmdArgs = append(chainCmdArgs, "{", "type", "filter", "hook", "input", "priority", "0", ";", "}")
	} else if strings.HasSuffix(strings.ToLower(chainName), "_forward") {
		chainCmdArgs = append(chainCmdArgs, "{", "type", "filter", "hook", "forward", "priority", "0", ";", "}")
	} else if strings.HasSuffix(strings.ToLower(chainName), "_output") {
		chainCmdArgs = append(chainCmdArgs, "{", "type", "filter", "hook", "output", "priority", "0", ";", "}")
	}
	// If no suffix match, create as a regular chain (no hook)
	_, _ = runCmdWithOutput(chainCmdArgs, "root", "", nil, 60)

	// Add rule to the dynamic table/chain
	args := []string{"nft"}
	switch cr.data.Method {
	case "-A":
		args = append(args, "add")
	case "-I":
		args = append(args, "insert")
	case "-R":
		args = append(args, "replace")
	case "-D":
		args = append(args, "delete")
	}
	// cr.data.Chain already contains the complete chain name
	args = append(args, "rule", family, tableName, chainName)

	// Determine IP version keyword based on family
	ipVersion := "ip"
	icmpProtocol := "icmp"
	if family == "ip6" {
		ipVersion = "ip6"
		icmpProtocol = "icmpv6"
	}

	if cr.data.Source != "" && cr.data.Source != "0.0.0.0/0" && cr.data.Source != "::/0" {
		args = append(args, ipVersion, "saddr", cr.data.Source)
	}

	if cr.data.Destination != "" && cr.data.Destination != "0.0.0.0/0" && cr.data.Destination != "::/0" {
		args = append(args, ipVersion, "daddr", cr.data.Destination)
	}

	if cr.data.Protocol != "all" {
		if cr.data.Protocol == "icmp" || cr.data.Protocol == "icmpv6" {
			args = append(args, ipVersion, "protocol", icmpProtocol)
			if cr.data.ICMPType != "" {
				args = append(args, icmpProtocol, "type", cr.data.ICMPType)
			}
		} else if cr.data.Protocol == "tcp" || cr.data.Protocol == "udp" {
			// For TCP/UDP, use proper nftables protocol syntax
			if len(cr.data.DPorts) > 0 {
				args = append(args, cr.data.Protocol)
				var portList []string
				for _, port := range cr.data.DPorts {
					portList = append(portList, strconv.Itoa(port))
				}
				args = append(args, "dport", "{", strings.Join(portList, ","), "}")
			} else if cr.data.PortStart != 0 {
				args = append(args, cr.data.Protocol)
				// Handle single port or port range
				if cr.data.PortEnd != 0 && cr.data.PortEnd != cr.data.PortStart {
					portStr := fmt.Sprintf("%d-%d", cr.data.PortStart, cr.data.PortEnd)
					args = append(args, "dport", portStr)
				} else {
					args = append(args, "dport", strconv.Itoa(cr.data.PortStart))
				}
			} else {
				// No port specified, use ip protocol syntax
				args = append(args, ipVersion, "protocol", cr.data.Protocol)
			}
		} else {
			// For other protocols
			args = append(args, ipVersion, "protocol", cr.data.Protocol)
		}
	}

	// Add target action (accept/drop/reject)
	targetAction := strings.ToLower(cr.data.Target)
	if targetAction == "accept" || targetAction == "drop" || targetAction == "reject" {
		args = append(args, targetAction)
	} else {
		// Default action if target is not specified or invalid
		args = append(args, "accept")
	}

	// Add comment with rule_id and rule_type
	if cr.data.RuleID != "" || cr.data.RuleType != "" {
		var commentParts []string
		if cr.data.RuleID != "" {
			commentParts = append(commentParts, fmt.Sprintf("rule_id:%s", cr.data.RuleID))
		}
		if cr.data.RuleType != "" {
			commentParts = append(commentParts, fmt.Sprintf("type:%s", cr.data.RuleType))
		}
		ruleComment := strings.Join(commentParts, ",")
		args = append(args, "comment", fmt.Sprintf("\"%s\"", ruleComment))
	}

	// Log the final nftables command
	log.Info().Msgf("Executing nftables command: %s", strings.Join(args, " "))

	exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)

	if exitCode != 0 {
		log.Error().Msgf("nftables command failed (exit code %d): %s", exitCode, result)
		return exitCode, fmt.Sprintf("nftables error: %s", result)
	}

	log.Info().Msgf("Successfully executed nftables rule for table %s (family: %s)", tableName, family)
	return 0, fmt.Sprintf("Successfully executed rule for security group table %s (family: %s).", tableName, family)
}

// getIptablesCommand returns the appropriate iptables command based on IP family
func (cr *CommandRunner) getIptablesCommand() string {
	switch cr.data.Family {
	case "ip6":
		return "ip6tables"
	case "arp":
		return "arptables"
	case "bridge":
		return "ebtables"
	case "inet", "netdev":
		// These are nftables-only families, should not be used with iptables
		// Fall back to iptables but log a warning
		log.Warn().Msgf("Family '%s' is nftables-only, falling back to iptables", cr.data.Family)
		return "iptables"
	default:
		// Default to iptables for ip (IPv4) or unspecified family
		return "iptables"
	}
}

// executeIptablesRule executes iptables rule
func (cr *CommandRunner) executeIptablesRule() (exitCode int, result string) {
	log.Info().Msg("Using iptables for firewall management.")

	// Determine which command to use based on family
	cmd := cr.getIptablesCommand()
	log.Info().Msgf("Using %s command for family: %s", cmd, cr.data.Family)

	// cr.data.Chain now contains the complete chain name (e.g., "alpacon-web_input")
	chainName := cr.data.Chain

	// Get table parameter (default to filter if not specified)
	table := cr.data.Table
	if table == "" {
		table = "filter"
	}

	// Create chain dynamically in specified table
	chainCreateCmdArgs := []string{cmd, "-t", table, "-N", chainName}
	_, _ = runCmdWithOutput(chainCreateCmdArgs, "root", "", nil, 60)

	// Add rule to the dynamic chain
	args := []string{cmd, "-t", table, cr.data.Method, chainName}

	// Add protocol
	if cr.data.Protocol != "all" {
		args = append(args, "-p", cr.data.Protocol)
	}

	// Add source if specified
	if cr.data.Source != "" && cr.data.Source != "0.0.0.0/0" {
		args = append(args, "-s", cr.data.Source)
	}

	// Add destination if specified
	if cr.data.Destination != "" && cr.data.Destination != "0.0.0.0/0" {
		args = append(args, "-d", cr.data.Destination)
	}

	// Handle ports based on protocol
	if cr.data.Protocol == "icmp" {
		if cr.data.ICMPType != "" {
			args = append(args, "--icmp-type", cr.data.ICMPType)
		}
	} else if cr.data.Protocol == "tcp" || cr.data.Protocol == "udp" {
		// Handle multiport
		if len(cr.data.DPorts) > 0 {
			var portList []string
			for _, port := range cr.data.DPorts {
				portList = append(portList, strconv.Itoa(port))
			}
			args = append(args, "-m", "multiport", "--dports", strings.Join(portList, ","))
		} else if cr.data.PortStart != 0 {
			// Handle single port or port range
			if cr.data.PortEnd != 0 && cr.data.PortEnd != cr.data.PortStart {
				portStr := fmt.Sprintf("%d:%d", cr.data.PortStart, cr.data.PortEnd)
				args = append(args, "--dport", portStr)
			} else {
				args = append(args, "--dport", strconv.Itoa(cr.data.PortStart))
			}
		}
	}

	// Add target
	args = append(args, "-j", cr.data.Target)

	// Add comment with rule_id and rule_type
	if cr.data.RuleID != "" || cr.data.RuleType != "" {
		var commentParts []string
		if cr.data.RuleID != "" {
			commentParts = append(commentParts, fmt.Sprintf("rule_id:%s", cr.data.RuleID))
		}
		if cr.data.RuleType != "" {
			commentParts = append(commentParts, fmt.Sprintf("type:%s", cr.data.RuleType))
		}
		ruleComment := strings.Join(commentParts, ",")
		args = append(args, "-m", "comment", "--comment", ruleComment)
	}

	// Log the final command
	log.Info().Msgf("Executing %s command: %s", cmd, strings.Join(args, " "))

	exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)

	if exitCode != 0 {
		log.Error().Msgf("%s command failed (exit code %d): %s", cmd, exitCode, result)
		return exitCode, fmt.Sprintf("%s error: %s", cmd, result)
	}

	log.Info().Msgf("Successfully executed %s rule for chain %s", cmd, chainName)
	return 0, fmt.Sprintf("Successfully executed rule for security group chain %s.", chainName)
}

// deleteNftablesRuleByID deletes a specific nftables rule by finding its handle using rule_id in comment
func (cr *CommandRunner) deleteNftablesRuleByID(chainName, ruleID string) (exitCode int, result string) {
	log.Info().Msgf("Deleting nftables rule by ID: %s in chain %s", ruleID, chainName)

	// Get table and family from cr.data (provided by server)
	family := cr.data.Family
	table := cr.data.Table

	// Default values if not provided
	if family == "" {
		family = "inet"  // Default family for nftables
	}
	if table == "" {
		table = "filter"  // Default table
	}

	log.Debug().Msgf("Using nftables family: %s, table: %s, chain: %s", family, table, chainName)

	// First, list rules with handles to find the target rule
	listArgs := []string{"nft", "--handle", "list", "table", family, table}
	listExitCode, listOutput := runCmdWithOutput(listArgs, "root", "", nil, 60)

	if listExitCode != 0 {
		log.Error().Msgf("Failed to list nftables rules: %s", listOutput)
		return listExitCode, fmt.Sprintf("Failed to list rules: %s", listOutput)
	}

	// Parse the output to find rule handle in the specific chain with matching rule_id in comment
	ruleHandle := cr.findNftablesRuleHandleInChain(listOutput, chainName, ruleID)
	if ruleHandle == "" {
		log.Warn().Msgf("Rule with ID %s not found in chain %s", ruleID, chainName)
		return 1, fmt.Sprintf("Rule with ID %s not found", ruleID)
	}

	// Delete the rule using its handle
	// nftables syntax: nft delete rule <family> <table> <chain> handle <handle>
	deleteArgs := []string{"nft", "delete", "rule", family, table, chainName, "handle", ruleHandle}
	deleteExitCode, deleteOutput := runCmdWithOutput(deleteArgs, "root", "", nil, 60)

	if deleteExitCode != 0 {
		log.Error().Msgf("Failed to delete nftables rule: %s", deleteOutput)
		return deleteExitCode, fmt.Sprintf("Failed to delete rule: %s", deleteOutput)
	}

	log.Info().Msgf("Successfully deleted nftables rule with ID %s (handle %s) from chain %s", ruleID, ruleHandle, chainName)
	return 0, fmt.Sprintf("Successfully deleted rule with ID %s", ruleID)
}

// findNftablesRuleHandleInChain parses nft list output to find rule handle in a specific chain by rule_id in comment
func (cr *CommandRunner) findNftablesRuleHandleInChain(listOutput, targetChain, ruleID string) string {
	lines := strings.Split(listOutput, "\n")
	targetComment := fmt.Sprintf("rule_id:%s", ruleID)
	currentChain := ""
	inTargetChain := false

	for _, line := range lines {
		// Check for chain declarations (e.g., "chain input {", "chain output {")
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "chain ") && strings.Contains(trimmed, "{") {
			// Extract chain name from "chain <name> {"
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				currentChain = parts[1]
				inTargetChain = (currentChain == targetChain)
			}
		}

		// Only look for rules in the target chain
		if inTargetChain {
			// Look for lines containing the target comment and handle
			if strings.Contains(line, targetComment) && strings.Contains(line, "# handle") {
				// Extract handle number from the line
				if handleIndex := strings.Index(line, "# handle"); handleIndex != -1 {
					handlePart := line[handleIndex+9:] // Skip "# handle "
					handle := ""
					if spaceIndex := strings.Index(handlePart, " "); spaceIndex != -1 {
						handle = strings.TrimSpace(handlePart[:spaceIndex])
					} else {
						handle = strings.TrimSpace(handlePart)
					}
					return handle
				}
			}
		}
	}

	return ""
}

// deleteIptablesRuleByID deletes a specific iptables rule by matching rule specifications
func (cr *CommandRunner) deleteIptablesRuleByID(chainName, ruleID string) (exitCode int, result string) {
	log.Info().Msgf("Deleting iptables rule - Chain: %s, RuleID: %s", chainName, ruleID)

	// chainName now contains the complete chain name (e.g., "alpacon-web_input")
	// No need to combine with cr.data.Chain

	// Note: For iptables rule deletion with comment, we rely on rule specification matching
	// since comment format may include additional type information

	// Get table parameter (default to filter if not specified)
	table := cr.data.Table
	if table == "" {
		table = "filter"
	}

	// Build delete command with rule specifications
	cmd := cr.getIptablesCommand()
	args := []string{cmd, "-t", table, "-D", chainName}

	// Add protocol
	if cr.data.Protocol != "" && cr.data.Protocol != "all" {
		args = append(args, "-p", cr.data.Protocol)
	}

	// Add source if specified
	if cr.data.Source != "" && cr.data.Source != "0.0.0.0/0" {
		args = append(args, "-s", cr.data.Source)
	}

	// Add destination if specified
	if cr.data.Destination != "" && cr.data.Destination != "0.0.0.0/0" {
		args = append(args, "-d", cr.data.Destination)
	}

	// Handle ports based on protocol
	if cr.data.Protocol == "icmp" {
		if cr.data.ICMPType != "" {
			args = append(args, "--icmp-type", cr.data.ICMPType)
		}
	} else if cr.data.Protocol == "tcp" || cr.data.Protocol == "udp" {
		// Handle multiport
		if len(cr.data.DPorts) > 0 {
			var portList []string
			for _, port := range cr.data.DPorts {
				portList = append(portList, strconv.Itoa(port))
			}
			args = append(args, "-m", "multiport", "--dports", strings.Join(portList, ","))
		} else if cr.data.PortStart != 0 {
			// Handle single port or port range
			if cr.data.PortEnd != 0 && cr.data.PortEnd != cr.data.PortStart {
				portStr := fmt.Sprintf("%d:%d", cr.data.PortStart, cr.data.PortEnd)
				args = append(args, "--dport", portStr)
			} else {
				args = append(args, "--dport", strconv.Itoa(cr.data.PortStart))
			}
		}
	}

	// Add target
	if cr.data.Target != "" {
		args = append(args, "-j", cr.data.Target)
	}

	// Skip comment matching for deletion since the comment format may have changed
	// to include type information. Rule specification matching should be sufficient.

	// Execute delete command
	deleteExitCode, deleteOutput := runCmdWithOutput(args, "root", "", nil, 60)

	if deleteExitCode != 0 {
		log.Error().Msgf("Failed to delete iptables rule: %s", deleteOutput)
		return deleteExitCode, fmt.Sprintf("Failed to delete rule: %s", deleteOutput)
	}

	log.Info().Msgf("Successfully deleted iptables rule with ID %s", ruleID)
	return 0, fmt.Sprintf("Successfully deleted rule with ID %s", ruleID)
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

func parsePaths(homeDirectory string, pathList []string) (parsedPaths []string, isBulk bool, isRecursive bool, err error) {
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

// validateFirewallData performs enhanced validation for firewall data
func (cr *CommandRunner) validateFirewallData(data firewallData) error {
	// Basic validation using struct tags
	if err := cr.validateData(data); err != nil {
		return fmt.Errorf("basic validation failed: %w", err)
	}

	// Enhanced validation logic
	validMethods := []string{"-A", "-I", "-R", "-D"}
	found := false
	for _, method := range validMethods {
		if data.Method == method {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("invalid method '%s', must be one of: %v", data.Method, validMethods)
	}

	validProtocols := []string{"tcp", "udp", "icmp", "all"}
	found = false
	for _, protocol := range validProtocols {
		if data.Protocol == protocol {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("invalid protocol '%s', must be one of: %v", data.Protocol, validProtocols)
	}

	validTargets := []string{"ACCEPT", "DROP", "REJECT", "LOG", "RETURN"}
	found = false
	for _, target := range validTargets {
		if data.Target == target {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("invalid target '%s', must be one of: %v", data.Target, validTargets)
	}

	// Protocol-specific validation
	if data.Protocol == "icmp" {
		if data.PortStart != 0 || data.PortEnd != 0 || len(data.DPorts) > 0 {
			return fmt.Errorf("ICMP protocol cannot have port specifications")
		}
	}

	// Port validation
	if data.PortStart != 0 {
		if data.PortStart < 1 || data.PortStart > 65535 {
			return fmt.Errorf("PortStart must be between 1 and 65535, got %d", data.PortStart)
		}
	}

	if data.PortEnd != 0 {
		if data.PortEnd < 1 || data.PortEnd > 65535 {
			return fmt.Errorf("PortEnd must be between 1 and 65535, got %d", data.PortEnd)
		}
		if data.PortStart != 0 && data.PortEnd < data.PortStart {
			return fmt.Errorf("PortEnd (%d) cannot be less than PortStart (%d)", data.PortEnd, data.PortStart)
		}
	}

	// DPorts validation
	if len(data.DPorts) > 0 {
		if len(data.DPorts) > 15 {
			return fmt.Errorf("too many ports in multiport rule (max 15), got %d", len(data.DPorts))
		}

		// Check for duplicates and validate range
		seen := make(map[int]bool)
		for _, port := range data.DPorts {
			if port < 1 || port > 65535 {
				return fmt.Errorf("DPort must be between 1 and 65535, got %d", port)
			}
			if seen[port] {
				return fmt.Errorf("duplicate port %d in DPorts", port)
			}
			seen[port] = true
		}

		// Cannot have both DPorts and single port/range
		if data.PortStart != 0 || data.PortEnd != 0 {
			return fmt.Errorf("cannot specify both individual ports (PortStart/PortEnd) and multiport (DPorts)")
		}
	}

	// ICMP type validation
	if data.Protocol == "icmp" && data.ICMPType != "" {
		// Check if numeric
		if icmpTypeNum, err := strconv.Atoi(data.ICMPType); err == nil {
			if icmpTypeNum < 0 || icmpTypeNum > 255 {
				return fmt.Errorf("ICMP type must be between 0 and 255, got %d", icmpTypeNum)
			}
		} else {
			// Validate common ICMP type names
			validICMPTypes := []string{
				"echo-request", "echo-reply", "destination-unreachable",
				"source-quench", "redirect", "time-exceeded",
				"parameter-problem", "timestamp-request", "timestamp-reply",
			}
			found := false
			for _, validType := range validICMPTypes {
				if data.ICMPType == validType {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("invalid ICMP type '%s'", data.ICMPType)
			}
		}
	} else if data.Protocol != "icmp" && data.ICMPType != "" {
		return fmt.Errorf("ICMP type can only be specified for ICMP protocol")
	}

	return nil
}

// firewallRollback handles firewall rollback operations
func (cr *CommandRunner) firewallRollback() (exitCode int, result string) {
	log.Info().Msgf("Firewall rollback command received - Operation: %s",
		cr.data.Operation)

	// Validate operation
	if cr.data.Operation == "" {
		return 1, "firewall-rollback: Operation is required"
	}

	// Determine the action (flush or restore)
	action := cr.data.Operation
	if action == "" {
		// Fallback to Method field for backward compatibility
		if cr.data.Method != "" {
			action = cr.data.Method
		} else {
			action = "flush" // Default action
		}
	}

	// Handle different rollback actions
	switch action {
	case "flush":
		// Flush operation is deprecated - use batch operations instead
		log.Warn().Msg("Flush operation is deprecated in rollback - use restore with empty rules")
		return 0, `{"success": true, "message": "Flush operation deprecated"}`

	case "restore":
		// Restore from snapshot - flush then apply new rules
		if len(cr.data.Rules) == 0 {
			log.Info().Msg("Restore with no rules - effectively a flush operation")
			return 0, `{"success": true, "message": "No rules to restore (flush effect)"}`
		}

		// No explicit flush needed - just apply the rules
		// The batch operation will handle chain management

		// Then apply each rule from the snapshot
		successCount := 0
		failedRules := []string{}

		for i, ruleData := range cr.data.Rules {
			// Convert rule data to CommandData fields using existing function with rule ID generation
			cr.data = cr.convertRuleDataToCommandData(ruleData, cr.data)

			ruleExitCode, ruleResult := cr.executeSingleFirewallRule()
			if ruleExitCode == 0 {
				successCount++
			} else {
				failedRules = append(failedRules, fmt.Sprintf("Rule %d: %s", i+1, ruleResult))
			}
		}

		if len(failedRules) > 0 {
			return 1, fmt.Sprintf("firewall-rollback: Restored %d/%d rules. Failed rules: %s",
				successCount, len(cr.data.Rules), strings.Join(failedRules, "; "))
		}

		return 0, fmt.Sprintf("firewall-rollback: Successfully restored %d rules", successCount)

	case "delete":
		// Delete operation is deprecated - chain deletion should be handled via batch operations
		log.Warn().Msg("Delete operation is deprecated in rollback")
		return 0, `{"success": true, "message": "Delete operation deprecated"}`

	default:
		return 1, fmt.Sprintf("firewall-rollback: Unknown action '%s', use 'flush', 'restore', or 'delete'", action)
	}

	return 1, "firewall-rollback: No firewall management tool installed"
}

// performNftablesRollback performs rollback operations for nftables
// Now supports both old format (table name only) and new format (family table chain)
func (cr *CommandRunner) performNftablesRollback(chainName, method string) (int, string) {
	log.Info().Msgf("Performing nftables rollback for chain: %s, method: %s", chainName, method)

	var exitCode int
	var result string

	// Parse chainName to extract family, table, and chain
	// Format can be:
	// 1. Old format: just table name (e.g., "alpacon-sg-123")
	// 2. New format: "family table chain" (e.g., "inet filter alpacon-sg-123_input")
	parts := strings.Fields(chainName)

	var family, table, chain string

	if len(parts) == 3 {
		// New format: family table chain
		family = parts[0]
		table = parts[1]
		chain = parts[2]
	} else if len(parts) == 1 {
		// Old format: treat as table name, use default family
		family = "inet"
		table = parts[0]
		chain = ""  // Will flush all chains in table
	} else {
		return 1, fmt.Sprintf("Invalid chain format: %s", chainName)
	}

	switch method {
	case "flush":
		if chain != "" {
			// Flush specific chain
			args := []string{"nft", "flush", "chain", family, table, chain}
			exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)

			if exitCode == 0 {
				log.Info().Msgf("Successfully flushed nftables chain: %s %s %s", family, table, chain)
				return 0, fmt.Sprintf("Successfully flushed chain %s in table %s %s", chain, family, table)
			} else {
				log.Error().Msgf("Failed to flush nftables chain %s %s %s: %s", family, table, chain, result)
				return exitCode, fmt.Sprintf("Failed to flush chain: %s", result)
			}
		} else {
			// Old behavior: flush all chains in the table
			chainTypes := []string{"input", "output", "forward"}
			successCount := 0

			for _, chainType := range chainTypes {
				args := []string{"nft", "flush", "chain", family, table, chainType}
				exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)

				if exitCode == 0 {
					successCount++
					log.Info().Msgf("Successfully flushed nftables chain: %s %s %s", family, table, chainType)
				} else {
					// Chain might not exist, which is OK
					log.Debug().Msgf("Failed to flush nftables chain %s %s %s: %s (chain may not exist)", family, table, chainType, result)
				}
			}

			if successCount > 0 {
				log.Info().Msgf("Successfully flushed %d chains in table %s %s", successCount, family, table)
				return 0, fmt.Sprintf("Successfully flushed %d chains in table %s %s", successCount, family, table)
			}

			log.Warn().Msgf("No chains flushed in table %s %s (table may not exist)", family, table)
			return 0, fmt.Sprintf("No chains to flush in table %s %s", family, table)
		}

	case "delete":
		// Delete the entire table
		args := []string{"nft", "delete", "table", "inet", chainName}
		exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)

		if exitCode != 0 {
			log.Error().Msgf("Failed to delete nftables table %s: %s", chainName, result)
			// If table doesn't exist, consider it success
			if strings.Contains(result, "No such file or directory") {
				log.Info().Msgf("nftables table %s already deleted", chainName)
				return 0, fmt.Sprintf("Table %s was already deleted", chainName)
			}
			return exitCode, fmt.Sprintf("nftables delete error: %s", result)
		}

		log.Info().Msgf("Successfully deleted nftables table: %s", chainName)
		return 0, fmt.Sprintf("Successfully deleted table %s", chainName)

	default:
		return 1, fmt.Sprintf("nftables rollback: unsupported method '%s', use 'flush' or 'delete'", method)
	}
}

// performIptablesRollback performs rollback operations for iptables
func (cr *CommandRunner) performIptablesRollback(chainName, method string) (int, string) {
	log.Info().Msgf("Performing iptables rollback for chain: %s, method: %s", chainName, method)

	var exitCode int
	var result string

	// Get the appropriate iptables command based on IP family
	cmd := cr.getIptablesCommand()

	// Get table parameter (default to filter if not specified)
	table := cr.data.Table
	if table == "" {
		table = "filter"
	}

	// For iptables, we need to handle chains differently
	chainTypes := []string{"input", "output", "forward"}

	switch method {
	case "flush":
		successCount := 0
		for _, chainType := range chainTypes {
			fullChainName := chainName + "_" + chainType

			// Flush the chain in the specified table
			args := []string{cmd, "-t", table, "-F", fullChainName}
			exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)

			if exitCode == 0 {
				successCount++
				log.Info().Msgf("Successfully flushed iptables chain: %s", fullChainName)
			} else {
				log.Warn().Msgf("Failed to flush iptables chain %s: %s", fullChainName, result)
			}
		}

		if successCount > 0 {
			return 0, fmt.Sprintf("Successfully flushed %d chains for security group %s", successCount, chainName)
		} else {
			return 1, fmt.Sprintf("Failed to flush any chains for security group %s", chainName)
		}

	case "delete":
		successCount := 0
		for _, chainType := range chainTypes {
			fullChainName := chainName + "_" + chainType

			// First flush the chain in the specified table
			flushArgs := []string{cmd, "-t", table, "-F", fullChainName}
			runCmdWithOutput(flushArgs, "root", "", nil, 60)

			// Then delete the chain from the specified table
			deleteArgs := []string{cmd, "-t", table, "-X", fullChainName}
			exitCode, result = runCmdWithOutput(deleteArgs, "root", "", nil, 60)

			if exitCode == 0 {
				successCount++
				log.Info().Msgf("Successfully deleted iptables chain: %s", fullChainName)
			} else {
				log.Warn().Msgf("Failed to delete iptables chain %s: %s", fullChainName, result)
			}
		}

		if successCount > 0 {
			return 0, fmt.Sprintf("Successfully deleted %d chains for security group %s", successCount, chainName)
		} else {
			return 1, fmt.Sprintf("Failed to delete any chains for security group %s", chainName)
		}

	default:
		return 1, fmt.Sprintf("iptables rollback: unsupported method '%s', use 'flush' or 'delete'", method)
	}
}

// applyRulesBatchWithFlush applies a batch of firewall rules with optional rollback on failure
// Returns: appliedRules, failedRules, rolledBack, rollbackReason
// flushBeforeApply: if true, flush all existing rules before applying new ones (full replacement)
//
//	if false, only add new rules (incremental)
func (cr *CommandRunner) applyRulesBatchWithFlush() (int, []map[string]interface{}, bool, string) {
	// Check firewall tools if needed
	_, _, err := utils.CheckFirewallTool()
	if err != nil {
		log.Error().Err(err).Msg("Failed to check firewall tools")
		return 0, nil, false, ""
	}

	// Backup current rules before applying changes
	backup, err := utils.BackupFirewallRules()
	if err != nil {
		log.Error().Err(err).Msg("Failed to create firewall backup")
		return 0, nil, false, fmt.Sprintf("Failed to create backup before applying rules: %v", err)
	}
	log.Info().Msg("Created firewall backup before batch apply")

	// Apply rules
	appliedRules := 0
	var failedRules []map[string]interface{}
	var rollbackReason string
	rolledBack := false

	// Store original data to restore later
	originalMethod := cr.data.Method
	originalChain := cr.data.Chain
	originalProtocol := cr.data.Protocol
	originalPortStart := cr.data.PortStart
	originalPortEnd := cr.data.PortEnd
	originalSource := cr.data.Source
	originalTarget := cr.data.Target
	originalDescription := cr.data.Description
	originalPriority := cr.data.Priority
	originalICMPType := cr.data.ICMPType
	originalDPorts := cr.data.DPorts

	defer func() {
		// Restore original data
		cr.data.Method = originalMethod
		cr.data.Chain = originalChain
		cr.data.Protocol = originalProtocol
		cr.data.PortStart = originalPortStart
		cr.data.PortEnd = originalPortEnd
		cr.data.Source = originalSource
		cr.data.Target = originalTarget
		cr.data.Description = originalDescription
		cr.data.Priority = originalPriority
		cr.data.ICMPType = originalICMPType
		cr.data.DPorts = originalDPorts
	}()

	for i, ruleData := range cr.data.Rules {
		// Convert rule data to CommandData fields
		cr.data = cr.convertRuleDataToCommandData(ruleData, cr.data)

		var ruleExitCode int
		var ruleResult string

		// Check if rule has an operation field for UUID-based operations
		if operation, ok := ruleData["operation"].(string); ok && operation != "" {
			// Handle UUID-based operations (update/delete/add)
			switch operation {
			case "update":
				// Update operation requires rule_id (new) and old_rule_id (to delete)
				ruleID, hasRuleID := ruleData["rule_id"].(string)
				oldRuleID, hasOldRuleID := ruleData["old_rule_id"].(string)

				if hasRuleID && ruleID != "" && hasOldRuleID && oldRuleID != "" {
					cr.data.RuleID = ruleID
					cr.data.OldRuleID = oldRuleID
					ruleExitCode, ruleResult = cr.handleUpdateOperation()
				} else {
					ruleExitCode = 1
					ruleResult = "update operation requires both rule_id (new) and old_rule_id (to delete)"
				}
			case "delete":
				// Delete operation requires rule_id
				if ruleID, ok := ruleData["rule_id"].(string); ok && ruleID != "" {
					cr.data.RuleID = ruleID
					ruleExitCode, ruleResult = cr.handleDeleteOperation()
				} else {
					ruleExitCode = 1
					ruleResult = "delete operation requires rule_id"
				}
			case "add":
				// Add operation - use handleAddOperation for proper validation and logging
				log.Debug().Msgf("Batch add operation for rule %d/%d", i+1, len(cr.data.Rules))
				ruleExitCode, ruleResult = cr.handleAddOperation()
			default:
				ruleExitCode = 1
				ruleResult = fmt.Sprintf("unknown operation: %s", operation)
			}
		} else {
			// Default: use method-based execution (-A, -I, -R, -D)
			// This applies validation and logging via handleAddOperation
			log.Debug().Msgf("Batch method-based operation for rule %d/%d (method: %s)", i+1, len(cr.data.Rules), cr.data.Method)
			ruleExitCode, ruleResult = cr.handleAddOperation()
		}

		if ruleExitCode == 0 {
			appliedRules++
			log.Info().Msgf("Successfully applied rule %d/%d", i+1, len(cr.data.Rules))
		} else {
			failedRule := map[string]interface{}{
				"rule":  fmt.Sprintf("Rule %d: %s", i+1, cr.data.Description),
				"error": ruleResult,
			}
			failedRules = append(failedRules, failedRule)
			log.Error().Msgf("Failed to apply rule %d/%d: %s", i+1, len(cr.data.Rules), ruleResult)

			// Trigger rollback on first failure if enabled
			if !rolledBack {
				rollbackReason = fmt.Sprintf("Rule %d failed to apply", i+1)
				rolledBack = true

				// Perform rollback to previous state
				log.Info().Msg("Initiating rollback due to rule failure")
				// Restore from backup
				if restoreErr := utils.RestoreFirewallRules(backup); restoreErr != nil {
					log.Error().Err(restoreErr).Msg("Failed to restore firewall rules from backup")
					rollbackReason = fmt.Sprintf("Rule %d failed and restore failed: %v", i+1, restoreErr)
				} else {
					log.Info().Msg("Successfully restored firewall rules from backup")
				}

				// Stop processing remaining rules
				break
			}
		}
	}

	return appliedRules, failedRules, rolledBack, rollbackReason
}

// convertRuleDataToCommandData converts rule data map to CommandData fields
func (cr *CommandRunner) convertRuleDataToCommandData(ruleData map[string]interface{}, data CommandData) CommandData {
	// Reset all optional fields to prevent conflicts between rules in batch operations
	// This ensures each rule starts with a clean slate
	data.Method = "-A" // Default to append
	data.Chain = ""
	data.Protocol = ""
	data.PortStart = 0
	data.PortEnd = 0
	data.DPorts = nil
	data.ICMPType = ""
	data.Source = ""
	data.Destination = ""
	data.Target = ""
	data.Description = ""
	data.Priority = 0
	data.RuleType = "alpacon" // Default to alpacon type
	data.RuleID = ""
	data.OldRuleID = ""

	// Backend-specific fields
	data.Backend = ""
	data.Table = ""
	data.Family = ""

	// Now set values from ruleData
	// Note: chain_name field is deprecated, use chain instead
	if method, ok := ruleData["method"].(string); ok {
		data.Method = method
	}
	if chain, ok := ruleData["chain"].(string); ok {
		data.Chain = chain
	}

	// Backend-specific fields
	if backend, ok := ruleData["backend"].(string); ok {
		data.Backend = backend
	}
	if table, ok := ruleData["table"].(string); ok {
		data.Table = table
	}
	if family, ok := ruleData["family"].(string); ok {
		data.Family = family
	}
	if protocol, ok := ruleData["protocol"].(string); ok {
		data.Protocol = protocol
	}
	if portStart, ok := ruleData["port_start"].(float64); ok {
		data.PortStart = int(portStart)
	}
	if portEnd, ok := ruleData["port_end"].(float64); ok {
		data.PortEnd = int(portEnd)
	}
	if source, ok := ruleData["source"].(string); ok {
		data.Source = source
	}
	if destination, ok := ruleData["destination"].(string); ok {
		data.Destination = destination
	}
	if target, ok := ruleData["target"].(string); ok {
		data.Target = target
	}
	if description, ok := ruleData["description"].(string); ok {
		data.Description = description
	}
	if priority, ok := ruleData["priority"].(float64); ok {
		data.Priority = int(priority)
	}
	if ruleType, ok := ruleData["rule_type"].(string); ok {
		data.RuleType = ruleType
	}
	if icmpType, ok := ruleData["icmp_type"].(string); ok {
		data.ICMPType = icmpType
	}
	if ruleID, ok := ruleData["rule_id"].(string); ok {
		data.RuleID = ruleID
	} else {
		// Generate rule ID if not provided
		data.RuleID = uuid.New().String()
	}

	// Handle operation field for batch operations (add, update, delete)
	if operation, ok := ruleData["operation"].(string); ok {
		data.Operation = operation
	}

	// Handle dports array
	if dportsInterface, ok := ruleData["dports"].([]interface{}); ok {
		dports := []int{}
		for _, p := range dportsInterface {
			if portStr, ok := p.(string); ok {
				if port, err := strconv.Atoi(portStr); err == nil {
					dports = append(dports, port)
				}
			} else if port, ok := p.(float64); ok {
				dports = append(dports, int(port))
			}
		}
		data.DPorts = dports
	}

	return data
}
