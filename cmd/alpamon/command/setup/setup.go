package setup

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"text/template"

	cli "github.com/alpacax/alpacon-cli/utils"
	"github.com/alpacax/alpamon/pkg/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	name             string
	configTarget     string
	templateFilePath string
)

type ConfigData struct {
	URL    string
	ID     string
	Key    string
	Verify string
	CACert string
	Debug  string
}

func SetConfigPaths(serviceName string) {
	name = serviceName
	configTarget = fmt.Sprintf("/etc/alpamon/%s.conf", name)
	templateFilePath = fmt.Sprintf("/etc/alpamon/%s.config.tmpl", name)
}

var SetupCmd = &cobra.Command{
	Use:   "setup",
	Short: fmt.Sprintf("Setup and configure the %s.", name),
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Printf("Starting %s setup...\n", name)

		var isOverwrite bool
		configExists := fileExists(configTarget)

		if configExists {
			fmt.Println("A configuration file already exists at:", configTarget)
			fmt.Println("When setting up non-interactively, the existing configuration file will be used.")

			if !term.IsTerminal(syscall.Stdin) {
				return nil
			}

			isOverwrite = cli.PromptForBool("Do you want to overwrite it with a new configuration?: ")
			if !isOverwrite {
				fmt.Println("Keeping the existing configuration file. Skipping configuration update.")
				return nil
			}
		}

		fmt.Println("Applying a new configuration automatically...")

		output, err := exec.Command("systemd-tmpfiles", "--create").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%w\n%s", err, string(output))
		}

		err = writeConfig()
		if err != nil {
			return err
		}

		fmt.Println("Configuration file successfully updated.")
		return nil
	},
}

func writeConfig() error {
	tmplData, err := os.ReadFile(templateFilePath)
	if err != nil {
		return fmt.Errorf("failed to read template config (%s): %v", templateFilePath, err)
	}

	tmpl, err := template.New(fmt.Sprintf("%s.conf", name)).Parse(string(tmplData))
	if err != nil {
		return fmt.Errorf("failed to parse template: %v", err)
	}

	configData := ConfigData{
		URL:    utils.GetEnvOrDefault("ALPACON_URL", ""),
		ID:     utils.GetEnvOrDefault("PLUGIN_ID", ""),
		Key:    utils.GetEnvOrDefault("PLUGIN_KEY", ""),
		Verify: utils.GetEnvOrDefault("ALPACON_SSL_VERIFY", "true"),
		CACert: utils.GetEnvOrDefault("ALPACON_CA_CERT", ""),
		Debug:  utils.GetEnvOrDefault("PLUGIN_DEBUG", "true"),
	}

	if configData.URL == "" || configData.ID == "" || configData.Key == "" {
		fmt.Println("Notice: Environment variables not set. Skipping config generation.")
		fmt.Println("Please run 'sudo alpamon register' to complete the registration.")
		return nil
	}

	err = os.MkdirAll(filepath.Dir(configTarget), 0755)
	if err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	targetFile, err := os.Create(configTarget)
	if err != nil {
		return fmt.Errorf("failed to create target config file: %v", err)
	}
	defer func() { _ = targetFile.Close() }()

	err = tmpl.Execute(targetFile, configData)
	if err != nil {
		return fmt.Errorf("failed to execute template into target file: %v", err)
	}

	return nil
}

func fileExists(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.Size() > 0
}
