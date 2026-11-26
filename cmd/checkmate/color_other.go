//go:build !windows

package main

import "os"

// enableColor reports whether the terminal shows ANSI colors. Terminals on
// POSIX systems do.
func enableColor(*os.File) bool { return true }
