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
		return cr.firewall()
	case "firewall-rollback":
		return cr.firewallRollback()
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

func installFirewall() (nftablesInstalled bool, iptablesInstalled bool, err error) {
	nftablesInstalled = false
	iptablesInstalled = false

	// Check if nftables is installed
	_, nftablesResult := runCmdWithOutput([]string{"which", "nft"}, "root", "", nil, 0)
	nftablesInstalled = strings.Contains(nftablesResult, "nft")

	if !nftablesInstalled {
		_, iptablesResult := runCmdWithOutput([]string{"which", "iptables"}, "root", "", nil, 0)
		iptablesInstalled = strings.Contains(iptablesResult, "iptables")
	}

	if nftablesInstalled || iptablesInstalled {
		return nftablesInstalled, iptablesInstalled, nil
	}

	// If neither is installed
	if !nftablesInstalled && !iptablesInstalled {
		log.Info().Msg("No firewall tools installed. Attempting to install nftables.")
		var installCmd []string
		if utils.PlatformLike == "debian" {
			updateCmd := []string{"apt-get", "update"}
			exitCode, result := runCmdWithOutput(updateCmd, "root", "", nil, 0)
			if exitCode != 0 {
				return false, false, fmt.Errorf("failed to update package list: %s", result)
			}
			installCmd = []string{"apt-get", "install", "-y", "nftables"}
		} else if utils.PlatformLike == "rhel" {
			installCmd = []string{"yum", "install", "-y", "nftables"}
		} else {
			return false, false, fmt.Errorf("unsupported operating system")
		}
		
		exitCode, _ := runCmdWithOutput(installCmd, "root", "", nil, 0)
		_, nftablesResult = runCmdWithOutput([]string{"which", "nft"}, "root", "", nil, 0)
		nftablesInstalled = strings.Contains(nftablesResult, "nft")
		if exitCode != 0 || !nftablesInstalled {
			log.Warn().Msg("Failed to install nftables. Attempting to install iptables.")
			
			if utils.PlatformLike == "debian" {
				installCmd = []string{"apt-get", "update", "&&", "apt-get", "install", "-y", "iptables"}
			} else if utils.PlatformLike == "rhel" {
				installCmd = []string{"yum", "install", "-y", "iptables"}
			}
			
			exitCode, _ = runCmdWithOutput(installCmd, "root", "", nil, 0)
			_, nftablesResult = runCmdWithOutput([]string{"which", "nft"}, "root", "", nil, 0)
			nftablesInstalled = strings.Contains(nftablesResult, "nft")
			if exitCode != 0 || !nftablesInstalled {
				return false, false, fmt.Errorf("failed to install firewall tools")
			}
		}
		
	}

	if !nftablesInstalled && !iptablesInstalled {
		return false, false, fmt.Errorf("failed to install firewall management tool")
	}

	return nftablesInstalled, iptablesInstalled, nil
}

func (cr *CommandRunner) firewall() (exitCode int, result string) {
	log.Info().Msgf("Firewall operation: %s, ChainName: %s", cr.data.Operation, cr.data.ChainName)

	// Validate required fields based on operation
	if cr.data.ChainName == "" {
		return 1, "firewall: chain_name is required"
	}
	if cr.data.Operation == "" {
		return 1, "firewall: operation is required"
	}

	// Route to appropriate operation handler
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
	default:
		return 1, fmt.Sprintf("firewall: Unknown operation '%s'. Supported: batch, flush, delete, add, update", cr.data.Operation)
	}
}

// handleBatchOperation handles batch application of firewall rules
func (cr *CommandRunner) handleBatchOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall batch operation - ChainName: %s, RuleCount: %d", 
		cr.data.ChainName, len(cr.data.Rules))
	
	if len(cr.data.Rules) == 0 {
		return 1, "firewall batch: No rules provided"
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

// handleFlushOperation handles flushing a firewall chain
func (cr *CommandRunner) handleFlushOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall flush operation - ChainName: %s", cr.data.ChainName)
	
	nftablesInstalled, iptablesInstalled, err := installFirewall()
	if err != nil {
		return 1, fmt.Sprintf("firewall flush: Failed to install firewall tools. %s", err)
	}
	
	if nftablesInstalled {
		return cr.performNftablesRollback(cr.data.ChainName, "flush")
	} else if iptablesInstalled {
		return cr.performIptablesRollback(cr.data.ChainName, "flush")
	}
	
	return 1, "firewall flush: No firewall management tool installed"
}

// handleDeleteOperation handles deleting a specific firewall rule by rule_id
func (cr *CommandRunner) handleDeleteOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall delete operation - ChainName: %s, RuleID: %s", cr.data.ChainName, cr.data.RuleID)
	
	// Validate required fields
	if cr.data.RuleID == "" {
		return 1, "firewall delete: rule_id is required for delete operation"
	}
	
	nftablesInstalled, iptablesInstalled, err := installFirewall()
	if err != nil {
		return 1, fmt.Sprintf("firewall delete: Failed to install firewall tools. %s", err)
	}
	
	if nftablesInstalled {
		return cr.deleteNftablesRuleByID(cr.data.ChainName, cr.data.RuleID)
	} else if iptablesInstalled {
		return cr.deleteIptablesRuleByID(cr.data.ChainName, cr.data.RuleID)
	}
	
	return 1, "firewall delete: No firewall management tool installed"
}

// handleAddOperation handles adding a single firewall rule
func (cr *CommandRunner) handleAddOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall add operation - ChainName: %s", cr.data.ChainName)
	
	// Validate required fields for rule addition
	if err := cr.validateFirewallRuleData(); err != nil {
		return 1, fmt.Sprintf("firewall add: Validation failed. %s", err)
	}
	
	return cr.executeSingleFirewallRule()
}

// handleUpdateOperation handles updating a firewall rule
func (cr *CommandRunner) handleUpdateOperation() (exitCode int, result string) {
	log.Info().Msgf("Firewall update operation - ChainName: %s", cr.data.ChainName)
	
	// Validate required fields for rule update
	if err := cr.validateFirewallRuleData(); err != nil {
		return 1, fmt.Sprintf("firewall update: Validation failed. %s", err)
	}
	
	return cr.executeSingleFirewallRule()
}

// validateFirewallRuleData performs validation for single rule operations
func (cr *CommandRunner) validateFirewallRuleData() error {
	// Set default rule type if not provided
	if cr.data.RuleType == "" {
		cr.data.RuleType = "user"
	}

	data := firewallData{
		ChainName:   cr.data.ChainName,
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
	nftablesInstalled, iptablesInstalled, err := installFirewall()
	if err != nil {
		return 1, fmt.Sprintf("firewall: Failed to install firewall tools. %s", err)
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
	
	// Create table dynamically
	tableCmdArgs := []string{"nft", "add", "table", "ip", cr.data.ChainName}
	_, _ = runCmdWithOutput(tableCmdArgs, "root", "", nil, 60)
	
	// Create chain in the new table
	chainCmdArgs := []string{"nft", "add", "chain", "ip", cr.data.ChainName, strings.ToLower(cr.data.Chain)}
	switch strings.ToUpper(cr.data.Chain) {
	case "INPUT":
		chainCmdArgs = append(chainCmdArgs, "{", "type", "filter", "hook", "input", "priority", strconv.Itoa(cr.data.Priority),";", "policy", "accept;", "}")
	case "OUTPUT":
		chainCmdArgs = append(chainCmdArgs, "{", "type", "filter", "hook", "output", "priority", strconv.Itoa(cr.data.Priority),";", "policy", "accept;", "}")
	case "FORWARD":
		chainCmdArgs = append(chainCmdArgs, "{", "type", "filter", "hook", "forward", "priority", strconv.Itoa(cr.data.Priority),";", "policy", "accept;", "}")
	default:
		chainCmdArgs = append(chainCmdArgs, "{", "type", "filter", "hook", "prerouting", "priority", strconv.Itoa(cr.data.Priority),";", "policy", "accept;", "}")
	}
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
	args = append(args, "rule", "ip", cr.data.ChainName, strings.ToLower(cr.data.Chain))
	
	if cr.data.Source != "" && cr.data.Source != "0.0.0.0/0" {
		args = append(args, "ip", "saddr", cr.data.Source)
	}

	if cr.data.Destination != "" && cr.data.Destination != "0.0.0.0/0" {
		args = append(args, "ip", "daddr", cr.data.Destination)
	}

	if cr.data.Protocol != "all" {
		if cr.data.Protocol == "icmp" {
			args = append(args, "ip", "protocol", cr.data.Protocol)
			if cr.data.ICMPType != "" {
				args = append(args, "icmp", "type", cr.data.ICMPType)
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
				args = append(args, "ip", "protocol", cr.data.Protocol)
			}
		} else {
			// For other protocols
			args = append(args, "ip", "protocol", cr.data.Protocol)
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
	
	exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)
	
	if exitCode != 0 {
		log.Error().Msgf("nftables command failed: %s", result)
		return exitCode, fmt.Sprintf("nftables error: %s", result)
	}
	
	log.Info().Msgf("Successfully executed nftables rule for table %s", cr.data.ChainName)
	return 0, fmt.Sprintf("Successfully executed rule for security group table %s.", cr.data.ChainName)
}

// executeIptablesRule executes iptables rule
func (cr *CommandRunner) executeIptablesRule() (exitCode int, result string) {
	log.Info().Msg("Using iptables for firewall management.")
	
	chainName := cr.data.ChainName+"_"+strings.ToLower(cr.data.Chain)

	// Create chain dynamically in filter table
	chainCreateCmdArgs := []string{"iptables", "-N", chainName}
	_, _ = runCmdWithOutput(chainCreateCmdArgs, "root", "", nil, 60)
	
	// Add rule to the dynamic chain
	args := []string{"iptables", cr.data.Method, chainName}
	
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
	
	exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)
	
	if exitCode != 0 {
		log.Error().Msgf("iptables command failed: %s", result)
		return exitCode, fmt.Sprintf("iptables error: %s", result)
	}
	
	log.Info().Msgf("Successfully executed iptables rule for chain %s", chainName)
	return 0, fmt.Sprintf("Successfully executed rule for security group chain %s.", chainName)
}

// deleteNftablesRuleByID deletes a specific nftables rule by finding its handle using rule_id in comment
func (cr *CommandRunner) deleteNftablesRuleByID(chainName, ruleID string) (exitCode int, result string) {
	log.Info().Msgf("Deleting nftables rule by ID: %s in chain %s", ruleID, chainName)
	
	// First, list rules with handles to find the target rule
	listArgs := []string{"nft", "--handle", "list", "table", "ip", chainName}
	listExitCode, listOutput := runCmdWithOutput(listArgs, "root", "", nil, 60)
	
	if listExitCode != 0 {
		log.Error().Msgf("Failed to list nftables rules: %s", listOutput)
		return listExitCode, fmt.Sprintf("Failed to list rules: %s", listOutput)
	}
	
	// Parse the output to find rule handle with matching rule_id in comment
	ruleHandle := cr.findNftablesRuleHandle(listOutput, ruleID)
	if ruleHandle == "" {
		log.Warn().Msgf("Rule with ID %s not found in chain %s", ruleID, chainName)
		return 1, fmt.Sprintf("Rule with ID %s not found", ruleID)
	}
	
	// Delete the rule using its handle
	deleteArgs := []string{"nft", "delete", "rule", "ip", chainName, cr.data.Chain, "handle", ruleHandle}
	deleteExitCode, deleteOutput := runCmdWithOutput(deleteArgs, "root", "", nil, 60)
	
	if deleteExitCode != 0 {
		log.Error().Msgf("Failed to delete nftables rule: %s", deleteOutput)
		return deleteExitCode, fmt.Sprintf("Failed to delete rule: %s", deleteOutput)
	}
	
	log.Info().Msgf("Successfully deleted nftables rule with ID %s (handle %s)", ruleID, ruleHandle)
	return 0, fmt.Sprintf("Successfully deleted rule with ID %s", ruleID)
}

// findNftablesRuleHandle parses nft list output to find rule handle by rule_id in comment
func (cr *CommandRunner) findNftablesRuleHandle(listOutput, ruleID string) string {
	lines := strings.Split(listOutput, "\n")
	targetComment := fmt.Sprintf("rule_id:%s", ruleID)

	for _, line := range lines {
		// Look for lines containing the target comment and handle
		// Comment format can be: "rule_id:xxx" or "rule_id:xxx,type:yyy"
		if strings.Contains(line, targetComment) && strings.Contains(line, "# handle") {
			// Extract handle number from the line
			// Example: "tcp dport { 80, 443 } counter accept # handle 5 comment \"rule_id:1d6de556-95ec-4d5e-b8e5-4f6fa874d335,type:user\""
			if handleIndex := strings.Index(line, "# handle"); handleIndex != -1 {
				handlePart := line[handleIndex+9:] // Skip "# handle "
				if spaceIndex := strings.Index(handlePart, " "); spaceIndex != -1 {
					return strings.TrimSpace(handlePart[:spaceIndex])
				} else {
					return strings.TrimSpace(handlePart)
				}
			}
		}
	}

	return ""
}

// deleteIptablesRuleByID deletes a specific iptables rule by matching rule specifications
func (cr *CommandRunner) deleteIptablesRuleByID(chainName, ruleID string) (exitCode int, result string) {
	log.Info().Msgf("Deleting iptables rule - ChainName: %s, RuleID: %s", chainName, ruleID)

	fullChainName := chainName + "_" + strings.ToLower(cr.data.Chain)

	// Note: For iptables rule deletion with comment, we rely on rule specification matching
	// since comment format may include additional type information
	
	// Build delete command with rule specifications
	args := []string{"iptables", "-D", fullChainName}
	
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
	log.Info().Msgf("Firewall rollback command received - Operation: %s, ChainName: %s", 
		cr.data.Operation, cr.data.ChainName)
	
	// Handle both old and new field names for backward compatibility
	if cr.data.ChainName == "" && cr.data.Operation == "" {
		return 1, "firewall-rollback: ChainName or Operation is required"
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
	
	nftablesInstalled, iptablesInstalled, err := installFirewall()
	if err != nil {
		log.Error().Err(err).Msg("Failed to install firewall tools for rollback")
		return 1, fmt.Sprintf("firewall-rollback: Failed to install firewall tools. %s", err)
	}
	
	// Handle different rollback actions
	switch action {
	case "flush":
		// Simple flush operation - remove all rules
		if nftablesInstalled {
			return cr.performNftablesRollback(cr.data.ChainName, "flush")
		} else if iptablesInstalled {
			return cr.performIptablesRollback(cr.data.ChainName, "flush")
		}
		
	case "restore":
		// Restore from snapshot - flush then apply new rules
		if len(cr.data.Rules) == 0 {
			return 1, "firewall-rollback: No rules provided for restore action"
		}
		
		// First flush the chain
		var flushExitCode int
		var flushResult string
		if nftablesInstalled {
			flushExitCode, flushResult = cr.performNftablesRollback(cr.data.ChainName, "flush")
		} else if iptablesInstalled {
			flushExitCode, flushResult = cr.performIptablesRollback(cr.data.ChainName, "flush")
		}
		
		if flushExitCode != 0 {
			return flushExitCode, fmt.Sprintf("firewall-rollback: Failed to flush before restore - %s", flushResult)
		}
		
		// Then apply each rule from the snapshot
		successCount := 0
		failedRules := []string{}
		
		for i, ruleData := range cr.data.Rules {
			// Convert rule data to CommandData fields
			if chainName, ok := ruleData["chain_name"].(string); ok {
				cr.data.ChainName = chainName
			}
			if method, ok := ruleData["method"].(string); ok {
				cr.data.Method = method
			}
			if chain, ok := ruleData["chain"].(string); ok {
				cr.data.Chain = chain
			}
			if protocol, ok := ruleData["protocol"].(string); ok {
				cr.data.Protocol = protocol
			}
			if portStart, ok := ruleData["port_start"].(float64); ok {
				cr.data.PortStart = int(portStart)
			}
			if portEnd, ok := ruleData["port_end"].(float64); ok {
				cr.data.PortEnd = int(portEnd)
			}
			if source, ok := ruleData["source"].(string); ok {
				cr.data.Source = source
			}
			if destination, ok := ruleData["destination"].(string); ok {
				cr.data.Destination = destination
			}
			if target, ok := ruleData["target"].(string); ok {
				cr.data.Target = target
			}
			if description, ok := ruleData["description"].(string); ok {
				cr.data.Description = description
			}
			if priority, ok := ruleData["priority"].(float64); ok {
				cr.data.Priority = int(priority)
			}
			if icmpType, ok := ruleData["icmp_type"].(string); ok {
				cr.data.ICMPType = icmpType
			}
			if ruleType, ok := ruleData["rule_type"].(string); ok {
				cr.data.RuleType = ruleType
			} else {
				cr.data.RuleType = "user" // Default to user type
			}
			
			// Handle dports array
			if dportsInterface, ok := ruleData["dports"].([]interface{}); ok {
				dports := []int{}
				for _, p := range dportsInterface {
					if port, ok := p.(float64); ok {
						dports = append(dports, int(port))
					}
				}
				cr.data.DPorts = dports
			}
			
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
		// Delete entire table/chain structure
		if nftablesInstalled {
			return cr.performNftablesRollback(cr.data.ChainName, "delete")
		} else if iptablesInstalled {
			return cr.performIptablesRollback(cr.data.ChainName, "delete")
		}

	default:
		return 1, fmt.Sprintf("firewall-rollback: Unknown action '%s', use 'flush', 'restore', or 'delete'", action)
	}
	
	return 1, "firewall-rollback: No firewall management tool installed"
}

// performNftablesRollback performs rollback operations for nftables
func (cr *CommandRunner) performNftablesRollback(chainName, method string) (int, string) {
	log.Info().Msgf("Performing nftables rollback for chain: %s, method: %s", chainName, method)
	
	var exitCode int
	var result string
	
	switch method {
	case "flush":
		// Flush all rules in the table
		args := []string{"nft", "flush", "table", "ip", chainName}
		exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)
		
		if exitCode != 0 {
			log.Error().Msgf("Failed to flush nftables table %s: %s", chainName, result)
			return exitCode, fmt.Sprintf("nftables flush error: %s", result)
		}
		
		log.Info().Msgf("Successfully flushed nftables table: %s", chainName)
		return 0, fmt.Sprintf("Successfully flushed table %s", chainName)
		
	case "delete":
		// Delete the entire table
		args := []string{"nft", "delete", "table", "ip", chainName}
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
	
	// For iptables, we need to handle chains differently
	chainTypes := []string{"input", "output", "forward"}
	
	switch method {
	case "flush":
		successCount := 0
		for _, chainType := range chainTypes {
			fullChainName := chainName + "_" + chainType
			
			// Flush the chain
			args := []string{"iptables", "-F", fullChainName}
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
			
			// First flush the chain
			flushArgs := []string{"iptables", "-F", fullChainName}
			runCmdWithOutput(flushArgs, "root", "", nil, 60)
			
			// Then delete the chain
			deleteArgs := []string{"iptables", "-X", fullChainName}
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
//                   if false, only add new rules (incremental)
func (cr *CommandRunner) applyRulesBatchWithFlush() (int, []map[string]interface{}, bool, string) {
	// Install firewall tools if needed
	nftablesInstalled, iptablesInstalled, err := installFirewall()
	if err != nil {
		log.Error().Err(err).Msg("Failed to install firewall tools")
		return 0, nil, false, ""
	}
	
	// Apply rules
	appliedRules := 0
	var failedRules []map[string]interface{}
	var rollbackReason string
	rolledBack := false
	
	// Store original data to restore later
	originalChainName := cr.data.ChainName
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
		cr.data.ChainName = originalChainName
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
		
		ruleExitCode, ruleResult := cr.executeSingleFirewallRule()
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
				
				// Perform rollback
				log.Info().Msg("Initiating rollback due to rule failure")
				if nftablesInstalled {
					cr.performNftablesRollback(originalChainName, "flush")
				} else if iptablesInstalled {
					cr.performIptablesRollback(originalChainName, "flush")
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
	if chainName, ok := ruleData["chain_name"].(string); ok {
		data.ChainName = chainName
	}
	if method, ok := ruleData["method"].(string); ok {
		data.Method = method
	} else {
		data.Method = "-A" // Default to append
	}
	if chain, ok := ruleData["chain"].(string); ok {
		data.Chain = chain
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
	} else {
		data.RuleType = "user" // Default to user type
	}
	if icmpType, ok := ruleData["icmp_type"].(string); ok {
		data.ICMPType = icmpType
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


// performNftablesChainDelete deletes a specific chain or table in nftables
func (cr *CommandRunner) performNftablesChainDelete(chainName string) (int, string) {
	log.Info().Msgf("Performing nftables chain delete for: %s", chainName)
	
	// Check if Chain field is provided for specific chain delete
	if cr.data.Chain != "" {
		// First flush the specific chain
		flushArgs := []string{"nft", "flush", "chain", "ip", chainName, strings.ToLower(cr.data.Chain)}
		runCmdWithOutput(flushArgs, "root", "", nil, 60)
		
		// Delete specific chain within the table
		args := []string{"nft", "delete", "chain", "ip", chainName, strings.ToLower(cr.data.Chain)}
		exitCode, result := runCmdWithOutput(args, "root", "", nil, 60)
		
		if exitCode != 0 {
			log.Error().Msgf("Failed to delete nftables chain %s.%s: %s", chainName, cr.data.Chain, result)
			// If chain doesn't exist, consider it success
			if strings.Contains(result, "No such file or directory") || strings.Contains(result, "does not exist") {
				log.Info().Msgf("nftables chain %s.%s doesn't exist, considering delete successful", chainName, cr.data.Chain)
				return 0, fmt.Sprintf("Chain %s.%s was already deleted or doesn't exist", chainName, cr.data.Chain)
			}
			return exitCode, fmt.Sprintf("nftables chain delete error: %s", result)
		}
		
		log.Info().Msgf("Successfully deleted nftables chain: %s.%s", chainName, cr.data.Chain)
		return 0, fmt.Sprintf("Successfully deleted chain %s.%s", chainName, cr.data.Chain)
	} else {
		// Delete entire table (all chains in the table)
		args := []string{"nft", "delete", "table", "ip", chainName}
		exitCode, result := runCmdWithOutput(args, "root", "", nil, 60)
		
		if exitCode != 0 {
			log.Error().Msgf("Failed to delete nftables table %s: %s", chainName, result)
			// If table doesn't exist, consider it success
			if strings.Contains(result, "No such file or directory") || strings.Contains(result, "does not exist") {
				log.Info().Msgf("nftables table %s doesn't exist, considering delete successful", chainName)
				return 0, fmt.Sprintf("Table %s was already deleted or doesn't exist", chainName)
			}
			return exitCode, fmt.Sprintf("nftables table delete error: %s", result)
		}
		
		log.Info().Msgf("Successfully deleted nftables table: %s", chainName)
		return 0, fmt.Sprintf("Successfully deleted table %s", chainName)
	}
}

// performIptablesChainDelete deletes specific chains in iptables
func (cr *CommandRunner) performIptablesChainDelete(chainName string) (int, string) {
	log.Info().Msgf("Performing iptables chain delete for: %s", chainName)
	
	var exitCode int
	var result string
	successCount := 0
	var failedChains []string
	
	if cr.data.Chain != "" {
		// Delete specific chain type
		fullChainName := chainName + "_" + strings.ToLower(cr.data.Chain)
		
		// First flush the chain
		flushArgs := []string{"iptables", "-F", fullChainName}
		runCmdWithOutput(flushArgs, "root", "", nil, 60)
		
		// Then delete the chain
		args := []string{"iptables", "-X", fullChainName}
		exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)
		
		if exitCode == 0 {
			log.Info().Msgf("Successfully deleted iptables chain: %s", fullChainName)
			return 0, fmt.Sprintf("Successfully deleted chain %s", fullChainName)
		} else {
			log.Error().Msgf("Failed to delete iptables chain %s: %s", fullChainName, result)
			// If chain doesn't exist, consider it success
			if strings.Contains(result, "No chain/target/match by that name") {
				log.Info().Msgf("iptables chain %s doesn't exist, considering delete successful", fullChainName)
				return 0, fmt.Sprintf("Chain %s was already deleted or doesn't exist", fullChainName)
			}
			return exitCode, fmt.Sprintf("iptables chain delete error: %s", result)
		}
	} else {
		// Delete all chain types for the security group
		chainTypes := []string{"input", "output", "forward"}
		
		for _, chainType := range chainTypes {
			fullChainName := chainName + "_" + chainType
			
			// First flush the chain
			flushArgs := []string{"iptables", "-F", fullChainName}
			runCmdWithOutput(flushArgs, "root", "", nil, 60)
			
			// Then delete the chain
			args := []string{"iptables", "-X", fullChainName}
			exitCode, result = runCmdWithOutput(args, "root", "", nil, 60)
			
			if exitCode == 0 {
				successCount++
				log.Info().Msgf("Successfully deleted iptables chain: %s", fullChainName)
			} else {
				log.Warn().Msgf("Failed to delete iptables chain %s: %s", fullChainName, result)
				// Don't add to failed chains if it simply doesn't exist
				if !strings.Contains(result, "No chain/target/match by that name") {
					failedChains = append(failedChains, fmt.Sprintf("%s (%s)", fullChainName, result))
				} else {
					successCount++ // Count non-existent chains as successful deletes
				}
			}
		}
		
		if len(failedChains) > 0 {
			return 1, fmt.Sprintf("Successfully deleted %d chains, failed chains: %s", successCount, strings.Join(failedChains, ", "))
		}
		
		return 0, fmt.Sprintf("Successfully deleted %d chains for security group %s", successCount, chainName)
	}
}
