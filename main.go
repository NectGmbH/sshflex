package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// StatusString represents the status of the response..
type StatusString string

const (
	// StatusStringSuccess means the action was successful.
	StatusStringSuccess = "Success"

	// StatusStringFailure means the action failed.
	StatusStringFailure = "Failure"

	// StatusStringNotSupported means the action is not supported.
	StatusStringNotSupported = "Not supported"
)

// Capabilities represents the features this flexvolume provider supports.
type Capabilities struct {
	Attach bool `json:"attach"`
}

// Response is the response to the kubelet from this very flex driver
type Response struct {
	Status       StatusString  `json:"status,omitempty"`
	Message      string        `json:"message,omitempty"`
	Capabilities *Capabilities `json:"capabilities,omitempty"`
}

// Options represents the options passed from kubelet to flexvolume for mounting the storage.
type Options struct {
	Host     string `json:"host"`
	Port     string `json:"port"`
	Path     string `json:"path"`
	User     string `json:"user"`
	Password string `json:"kubernetes.io/secret/password"`
	GID      string `json:"kubernetes.io/fsGroup"`
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "sshflex",
		Short: "sshfs flexvolume driver",
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "init",
		Short: "Initializes the flex driver",
		Run:   cmdInit,
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "mount [mount dir] [json options]",
		Short: "Mounts the remote ssh host",
		Run:   cmdMount,
		Args:  cobra.ExactArgs(2),
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "unmount [mount dir]",
		Short: "Unmounts the passed mount",
		Run:   cmdUnmount,
		Args:  cobra.ExactArgs(1),
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "attach",
		Short: "Unsupported",
		Run:   cmdNotSupport,
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "detach",
		Short: "Unsupported",
		Run:   cmdNotSupport,
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "waitforattach",
		Short: "Unsupported",
		Run:   cmdNotSupport,
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "isattached",
		Short: "Unsupported",
		Run:   cmdNotSupport,
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "mountdevice",
		Short: "Unsupported",
		Run:   cmdNotSupport,
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "unmountdevice",
		Short: "Unsupported",
		Run:   cmdNotSupport,
	})

	err := rootCmd.Execute()
	if err != nil {
		writeResponseAndExit(Response{
			Status:  StatusStringNotSupported,
			Message: err.Error(),
		})
	}
}

func cmdInit(cmd *cobra.Command, args []string) {
	writeResponseAndExit(Response{
		Status:       StatusStringSuccess,
		Capabilities: &Capabilities{Attach: false},
	})
}

func cmdNotSupport(cmd *cobra.Command, args []string) {
	writeResponseAndExit(Response{
		Status: StatusStringNotSupported,
	})
}

func cmdMount(cmd *cobra.Command, args []string) {
	mountDir := args[0]

	var opts Options
	err := json.Unmarshal([]byte(args[1]), &opts)
	if err != nil {
		writeResponseAndExit(Response{
			Status:  StatusStringFailure,
			Message: fmt.Sprintf("couldn't deserialize json opts, see: %v", err),
		})
	}

	if opts.Port == "" {
		opts.Port = "22"
	}

	if opts.Host == "" || opts.User == "" || opts.Password == "" {
		writeResponseAndExit(Response{
			Status:  StatusStringFailure,
			Message: "missing either host or user or password",
		})
	}

	decodedPW, err := base64.StdEncoding.DecodeString(opts.Password)
	if err != nil {
		writeResponseAndExit(Response{
			Status:  StatusStringFailure,
			Message: "couldnt decode password",
		})
	}

	opts.Password = string(decodedPW)

	sshfsArgs := []string{
		fmt.Sprintf("%s@%s:%s", opts.User, opts.Host, opts.Path),
		mountDir,
		"-o", "reconnect",
		"-o", "password_stdin",
		"-p", opts.Port,
		"-o", "IdentityFile=/dev/null",
		"-o", "allow_other",
		"-o", "UserKnownHostsFile=/dev/null", // FIXME: Allow specifying of host key using opts?
		"-o", "StrictHostKeyChecking=no",
	}

	if opts.GID != "" {
		sshfsArgs = append(sshfsArgs, "-o", "gid="+opts.GID)
	}

	proc := exec.Command("sshfs", sshfsArgs...)

	stdin, err := proc.StdinPipe()

	go (func() {
		defer stdin.Close()
		io.WriteString(stdin, opts.Password+"\n")
	})()

	stdout, err := proc.CombinedOutput()
	if err != nil {
		writeResponseAndExit(Response{
			Status:  StatusStringFailure,
			Message: fmt.Sprintf("couldn't exec sshfs, see: %s %v", string(stdout), err),
		})
	}

	writeResponseAndExit(Response{
		Status: StatusStringSuccess,
	})
}

func cmdUnmount(cmd *cobra.Command, args []string) {
	proc := exec.Command("umount", args[0])
	stdout, err := proc.Output()
	if err != nil {
		writeResponseAndExit(Response{
			Status:  StatusStringFailure,
			Message: fmt.Sprintf("couldn't umount `%s`, see: %s %v", args[0], string(stdout), err),
		})
	}

	writeResponseAndExit(Response{
		Status: StatusStringSuccess,
	})
}

func writeResponseAndExit(resp Response) {
	buf, _ := json.Marshal(resp)
	fmt.Println(string(buf))

	if resp.Status == StatusStringSuccess {
		os.Exit(0)
	} else if resp.Status == StatusStringFailure {
		os.Exit(1)
	} else {
		os.Exit(2)
	}
}
