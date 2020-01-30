package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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

const (
	// EncryptedSubPath is the subfolder where sshfs gets mounted.
	EncryptedSubPath = "encrypted/"

	// DecryptedSubPath is the subfolder where gocryptfs gets mounted.
	DecryptedSubPath = "decrypted/"
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
	Host                 string `json:"host"`
	Port                 string `json:"port"`
	Path                 string `json:"path"`
	User                 string `json:"user"`
	Password             string `json:"kubernetes.io/secret/password"`
	EncryptionPassphrase string `json:"kubernetes.io/secret/encryptionPassphrase"`
	GID                  string `json:"kubernetes.io/fsGroup"`
	Encrypt              string `json:"encrypt"`
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
	baseDir := args[0]
	opts := parseOptsOrExit([]byte(args[1]))
	shouldEncrypt := strings.ToLower(opts.Encrypt) == "true"
	sshfsMountDir := baseDir
	gocryptfsMountDir := filepath.Join(baseDir, DecryptedSubPath)

	if shouldEncrypt {
		err := mountTMPFS(baseDir)
		if err != nil {
			writeResponseAndExit(Response{
				Status:  StatusStringFailure,
				Message: fmt.Sprintf("couldn't mount tmpfs to `%s`, see: %v", baseDir, err),
			})
		}

		sshfsMountDir = filepath.Join(baseDir, EncryptedSubPath)

		err = os.Mkdir(sshfsMountDir, 777)
		if err != nil {
			writeResponseAndExit(Response{
				Status:  StatusStringFailure,
				Message: fmt.Sprintf("couldn't mkdir `%s`, see: %v", sshfsMountDir, err),
			})
		}

		err = os.Mkdir(gocryptfsMountDir, 777)
		if err != nil {
			writeResponseAndExit(Response{
				Status:  StatusStringFailure,
				Message: fmt.Sprintf("couldn't mkdir `%s`, see: %v", gocryptfsMountDir, err),
			})
		}
	}

	err := mountSSHFS(sshfsMountDir, opts)
	if err != nil {
		errorExitAndCleanup(fmt.Errorf("couldn't mount sshfs, see: %v", err), baseDir)
	}

	if shouldEncrypt {
		initialized, err := isPathGoCryptInitialized(sshfsMountDir)
		if err != nil {
			errorExitAndCleanup(fmt.Errorf("couldn't check if gocryptfs is already initialized, see: %v", err), sshfsMountDir, baseDir)
		}

		if !initialized {
			err := initializeGoCryptFS(sshfsMountDir, opts.EncryptionPassphrase)
			if err != nil {
				errorExitAndCleanup(fmt.Errorf("couldn't initialize gocryptfs, see: %v", err), sshfsMountDir, baseDir)
			}
		}

		err = mountGoCryptFS(sshfsMountDir, gocryptfsMountDir, opts)
		if err != nil {
			errorExitAndCleanup(fmt.Errorf("couldn't mount gocryptfs, see: %v", err), sshfsMountDir, baseDir)
		}
	}

	writeResponseAndExit(Response{
		Status: StatusStringSuccess,
	})
}

func errorExitAndCleanup(err error, mountDirs ...string) {
	for _, mountDir := range mountDirs {
		err2 := umount(mountDir)
		if err2 != nil {
			err = fmt.Errorf("%v, could not cleanup leaking mountpoint at %s", err, err2)
		}
	}

	writeResponseAndExit(Response{
		Status:  StatusStringFailure,
		Message: fmt.Sprintf("%v", err),
	})
}

func initializeGoCryptFS(mountDir string, passphrase string) error {

	proc := exec.Command("gocryptfs", "-init", "-q", mountDir)

	stdin, err := proc.StdinPipe()
	if err != nil {
		return fmt.Errorf("couldn't create stdin pipe, see: %v", err)
	}

	go (func() {
		defer stdin.Close()
		io.WriteString(stdin, passphrase+"\n")
	})()

	stdout, err := proc.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", stdout, err)
	}

	return nil
}

func isPathGoCryptInitialized(mountDir string) (bool, error) {
	gocryptfsconf := filepath.Join(mountDir, "gocryptfs.conf")
	_, err := os.Stat(gocryptfsconf)
	if os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("couldn't stat %s, see: %v", gocryptfsconf, err)
	}

	return true, nil
}

func mountGoCryptFS(cipherDir string, mountDir string, opts *Options) error {
	proc := exec.Command("gocryptfs", "-q", cipherDir, mountDir)

	stdin, err := proc.StdinPipe()
	if err != nil {
		return fmt.Errorf("couldn't create stdin pipe, see: %v", err)
	}

	go (func() {
		defer stdin.Close()
		io.WriteString(stdin, opts.EncryptionPassphrase+"\n")
	})()

	stdout, err := proc.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", stdout, err)
	}

	return nil
}

func mountTMPFS(mountDir string) error {
	proc := exec.Command("mount", "-t", "tmpfs", "-o", "size=1m", "tmpfs", mountDir)
	stdout, err := proc.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", stdout, err)
	}

	return nil
}

func mountSSHFS(mountDir string, opts *Options) error {
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
	if err != nil {
		return fmt.Errorf("couldn't create stdin pipe, see: %v", err)
	}

	go (func() {
		defer stdin.Close()
		io.WriteString(stdin, opts.Password+"\n")
	})()

	stdout, err := proc.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", stdout, err)
	}

	return nil
}

func umount(path string) error {
	proc := exec.Command("umount", path)
	stdout, err := proc.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v", stdout, err)
	}

	return nil
}

func cmdUnmount(cmd *cobra.Command, args []string) {
	baseDir := args[0]

	isCrypt, err := isCryptMountpoint(baseDir)
	if err != nil {
		writeResponseAndExit(Response{
			Status:  StatusStringFailure,
			Message: fmt.Sprintf("couldn't find out if `%s` is an encrypted mount, see: %v", baseDir, err),
		})
	}

	if isCrypt {
		encPath := filepath.Join(baseDir, EncryptedSubPath)
		dencPath := filepath.Join(baseDir, DecryptedSubPath)

		errGoCryptFS := umount(dencPath)
		errSSHFS := umount(encPath)
		errTMPFS := umount(baseDir)

		if errGoCryptFS != nil || errSSHFS != nil || errTMPFS != nil {
			writeResponseAndExit(Response{
				Status:  StatusStringFailure,
				Message: fmt.Sprintf("couldn't umount `%s`, sshfs: %v gocryptfs: %v tmpfs: %v", baseDir, errSSHFS, errGoCryptFS, errTMPFS),
			})
		}

		writeResponseAndExit(Response{
			Status: StatusStringSuccess,
		})
	} else {
		err = umount(baseDir)
		if err != nil {
			writeResponseAndExit(Response{
				Status:  StatusStringFailure,
				Message: fmt.Sprintf("couldn't umount `%s`, see: %v", baseDir, err),
			})
		}

		writeResponseAndExit(Response{
			Status: StatusStringSuccess,
		})
	}
}

func isCryptMountpoint(path string) (bool, error) {
	buf, err := ioutil.ReadFile("/proc/mounts")
	if err != nil {
		return false, fmt.Errorf("couldn't read /proc/mounts, see: %v", err)
	}

	strBuf := string(buf)

	encPath := filepath.Join(path, EncryptedSubPath)
	dencPath := filepath.Join(path, DecryptedSubPath)

	if strings.Contains(strBuf, " "+encPath+" ") || strings.Contains(strBuf, " "+dencPath+" ") {
		return true, nil
	}

	return false, nil
}

func writeResponseAndExit(resp Response) {
	buf, err := json.Marshal(resp)
	if err != nil {
		fmt.Printf("couldn't marshal response, see: %v\n", err)
		os.Exit(100)
	}

	fmt.Println(string(buf))

	if resp.Status == StatusStringSuccess {
		os.Exit(0)
	} else if resp.Status == StatusStringFailure {
		os.Exit(1)
	} else if resp.Status == StatusStringNotSupported {
		os.Exit(2)
	} else {
		os.Exit(3)
	}
}

func parseOptsOrExit(buf []byte) *Options {
	var opts Options
	err := json.Unmarshal(buf, &opts)
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
			Message: fmt.Sprintf("couldnt decode password, see: %v", err),
		})
	}

	opts.Password = string(decodedPW)

	if strings.ToLower(opts.Encrypt) == "true" {
		if opts.EncryptionPassphrase == "" {
			writeResponseAndExit(Response{
				Status:  StatusStringFailure,
				Message: "encrypt=true but no encryptionPassphrase specified in secret.",
			})
		}

		decodedPassphrase, err := base64.StdEncoding.DecodeString(opts.EncryptionPassphrase)
		if err != nil {
			writeResponseAndExit(Response{
				Status:  StatusStringFailure,
				Message: fmt.Sprintf("couldnt decode encryptionPassphrase, see: %v", err),
			})
		}

		opts.EncryptionPassphrase = string(decodedPassphrase)
	}

	return &opts
}
