package runner

import "testing"

func TestWindowsPowerShellModulePath(t *testing.T) {
	in := `C:\Users\me\Documents\PowerShell\Modules;C:\Program Files\PowerShell\Modules;` +
		`c:\program files\powershell\7\Modules;C:\Program Files\WindowsPowerShell\Modules;` +
		`C:\Windows\system32\WindowsPowerShell\v1.0\Modules;D:\Tools\MyModules`
	want := `C:\Program Files\WindowsPowerShell\Modules;` +
		`C:\Windows\system32\WindowsPowerShell\v1.0\Modules;D:\Tools\MyModules`
	if got := windowsPowerShellModulePath(in); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	if got := windowsPowerShellModulePath(want); got != want {
		t.Errorf("a clean path changed: %s", got)
	}
}
