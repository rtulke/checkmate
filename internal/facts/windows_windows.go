//go:build windows

package facts

import (
	"strconv"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// windowsDetails reads the product from the registry. ProductName is not
// reliable (Windows 11 still reports "Windows 10"), so the edition is derived
// from InstallationType and the build number.
func windowsDetails(f *Facts) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	installType, _, _ := k.GetStringValue("InstallationType")
	buildText, _, _ := k.GetStringValue("CurrentBuild")
	build, _ := strconv.Atoi(buildText)
	f.DistroName = windowsProduct(installType, build)
}

// windowsElevated reports whether the process runs with administrator rights.
func windowsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}
