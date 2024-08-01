//go:build !windows

package Endpoint

import "syscall"

func procAttrs(cmd []string) *syscall.SysProcAttr {
	return nil
}
