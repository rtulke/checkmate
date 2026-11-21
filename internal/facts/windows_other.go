//go:build !windows

package facts

func windowsDetails(*Facts) {}

func windowsElevated() bool { return false }
