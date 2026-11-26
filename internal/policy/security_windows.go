//go:build windows

package policy

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Replaced in tests.
var elevated = func() bool { return windows.GetCurrentProcessToken().IsElevated() }

// Rights that let someone change what a file contains or who may do so.
const writeRights = windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.DELETE |
	windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL

// checkFileSecurity refuses policy and waiver files that a user without
// administrator rights could have modified when checkmate runs elevated:
// policies are code executed with those rights.
//
// The access control list of the file and of its directory must not let
// Everyone, Authenticated Users or Users write. The directory counts
// because whoever can write there can replace the file.
func checkFileSecurity(path string) error {
	if !elevated() {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for _, target := range []string{abs, filepath.Dir(abs)} {
		who, err := writableByUsers(target)
		if err != nil {
			return fmt.Errorf("%s: cannot read the access control list of %s: %w", path, target, err)
		}
		if who != "" {
			return fmt.Errorf("%s: refusing to load a policy file with administrator rights: %s may write to %s "+
				"(remove that right, e.g. icacls \"%s\" /inheritance:r /grant Administrators:F /grant SYSTEM:F, "+
				"or pass --allow-insecure-policy)", path, who, target, target)
		}
	}
	return nil
}

// writableByUsers returns the name of a group of ordinary users that may
// write to path, or "" if there is none.
func writableByUsers(path string) (string, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return "", err
	}
	if dacl == nil {
		return "everyone (the file has no access control list)", nil
	}
	broad := map[string]windows.WELL_KNOWN_SID_TYPE{
		"Everyone":            windows.WinWorldSid,
		"Authenticated Users": windows.WinAuthenticatedUserSid,
		"Users":               windows.WinBuiltinUsersSid,
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return "", err
		}
		// Entries that only pass rights on to files created later do not
		// apply to the object itself.
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Mask&writeRights == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for name, kind := range broad {
			if sid.IsWellKnown(kind) {
				return name, nil
			}
		}
	}
	return "", nil
}
