package update

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/pkg/errors"
)

type Updater struct {
	libexecDir string
}

func NewUpdater(libexecDir string) (*Updater, error) {
	libexecDir, err := filepath.Abs(libexecDir)
	if err != nil {
		return nil, errors.Wrap(err, "Invalid libexec path")
	}

	return &Updater{libexecDir: libexecDir}, nil
}

func (u *Updater) Check() (updates map[string]string, err error) {
	var out bytes.Buffer
	cmd := exec.Command(path.Join(u.libexecDir, "check-update"))
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		err = errors.Wrap(err, "Failed to check for updates")
		return
	}

	dec := json.NewDecoder(&out)
	if err = dec.Decode(&updates); err != nil {
		err = errors.Wrap(err, "Failed to decode output")
		return
	}
	return
}

func (u *Updater) Update() error {
	cmd := exec.Command(path.Join(u.libexecDir, "update"))
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		err = errors.Wrap(err, "Failed to update")
	}
	return err
}

func (u *Updater) Upgrade() error {
	cmd := exec.Command(path.Join(u.libexecDir, "upgrade"))
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		err = errors.Wrap(err, "Failed to upgrade")
	}
	return err
}

func (u *Updater) UpgradeInBackground() error {
	cmd := exec.Command("systemctl", "start", "--wait", "fruitnanny-upgrade.service")
	if err := cmd.Run(); err != nil {
		return errors.Wrap(err, "Failed to upgrade")
	}
	return nil
}
