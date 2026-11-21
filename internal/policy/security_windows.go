//go:build windows

package policy

// checkFileSecurity is not implemented on Windows yet; ACL checks would
// require the Windows security API.
func checkFileSecurity(_ string) error { return nil }
