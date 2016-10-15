package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/blang/semver"
	"github.com/spf13/cobra"
)

var (
	file string
)

func main() {

	cmdMajor := &cobra.Command{
		Use: "major",
		Run: func(cmd *cobra.Command, args []string) {
			set(bump(major, get()))
		},
	}
	cmdMinor := &cobra.Command{
		Use: "minor",
		Run: func(cmd *cobra.Command, args []string) {
			set(bump(minor, get()))
		},
	}
	cmdPatch := &cobra.Command{
		Use: "patch",
		Run: func(cmd *cobra.Command, args []string) {
			set(bump(patch, get()))
		},
	}
	cmdSet := &cobra.Command{
		Use: "set",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				cmd.Usage()
				os.Exit(3)
			}
			v, err := semver.Make(strings.TrimSpace(args[0]))
			if err != nil {
				fmt.Printf("Invalid version (%s): %v", string(args[0]), err)
				os.Exit(2)
			}
			set(v)
		},
	}

	rootCmd := &cobra.Command{Use: "gobump"}
	rootCmd.PersistentFlags().StringVarP(&file, "file", "f", "VERSION", "version file")
	rootCmd.AddCommand(cmdMajor, cmdMinor, cmdPatch, cmdSet)
	rootCmd.Execute()
}

type versionPart string

const (
	major versionPart = "major"
	minor versionPart = "minor"
	patch versionPart = "patch"
)

func get() semver.Version {
	s, err := ioutil.ReadFile(file)
	if err != nil {
		fmt.Printf("Cannot read version file: %v", err)
		os.Exit(1)
	}
	v, err := semver.Make(strings.TrimSpace(string(s)))
	if err != nil {
		fmt.Printf("Invalid version (%s): %v", string(s), err)
		os.Exit(2)
	}
	return v
}

func bump(p versionPart, v semver.Version) semver.Version {
	switch p {
	case major:
		v.Major++
		v.Minor = 0
		v.Patch = 0
	case minor:
		v.Minor++
		v.Patch = 0
	case patch:
		v.Patch++
	}
	return v
}

func set(v semver.Version) {
	err := ioutil.WriteFile(file, []byte(v.String()), os.ModeExclusive)
	if err != nil {
		fmt.Printf("Unable to write version file: %v", err)
		os.Exit(3)
	}
	fmt.Printf("New version: %s", v)
}
