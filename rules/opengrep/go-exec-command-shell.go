//go:build ignore

// Annotated test file for go-exec-command-shell. Deliberately vulnerable: do not run.
package sample

import (
	"context"
	"fmt"
	"os/exec"
)

func ping(host string) error {
	// ruleid: go-exec-command-shell
	return exec.Command("sh", "-c", "ping -c 1 "+host).Run()
}

func archive(ctx context.Context, name string) error {
	cmd := fmt.Sprintf("tar czf %s.tgz %s", name, name)
	// ruleid: go-exec-command-shell
	return exec.CommandContext(ctx, "/bin/bash", "-c", cmd).Run()
}

func pingDirect(host string) error {
	// ok: go-exec-command-shell
	return exec.Command("ping", "-c", "1", host).Run()
}

func constant() error {
	// ok: go-exec-command-shell
	return exec.Command("sh", "-c", "ls -l /tmp").Run()
}
