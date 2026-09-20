package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   binaryName(),
	Short: "A command-line Minecraft launcher",
	Long:  `Shulker is a CLI Minecraft launcher.`,
}

func binaryName() string {
	name := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	if name == "minecraft" {
		return name
	}
	return "shulker"
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
