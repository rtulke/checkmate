//go:build windows

package main

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableColor turns on the processing of ANSI escape sequences for the
// console and reports whether that worked. Windows Terminal has it on;
// the classic console window (conhost) needs to be asked, and consoles
// before Windows 10 cannot do it at all.
func enableColor(f *os.File) bool {
	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	return windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
}
