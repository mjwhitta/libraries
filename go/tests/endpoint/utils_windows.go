//go:build windows

package Endpoint

import (
	"strings"
	"syscall"
)

func procAttrs(cmd []string) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CmdLine: strings.Join(cmd, " "),
	}
}
