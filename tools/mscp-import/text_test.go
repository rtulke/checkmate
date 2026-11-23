package main

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAsciidocText(t *testing.T) {
	in := "Gatekeeper _MUST_ be enabled for $ODV.\n\n" +
		"[IMPORTANT]\n====\nStealth mode may block *remote* scans.\n====\n\n" +
		"link:https://support.apple.com/HT207005[]\nSee link:https://example.com/a[the guide] and <<ref,the rule>>.\n\n" +
		"NOTE: run `defaults read x`.\n\n" +
		"* first\n* second\n\n" +
		". Go to System Settings\n. Click *Use Disk*\n\n" +
		"[source,bash]\n----\nsed 's/\\* file/x_y_z/' *.conf <<EOF\n$ODV\nEOF\n----\n"
	want := "Gatekeeper MUST be enabled for ^(?=.*[A-Z]).*$.\n\n" +
		"IMPORTANT: Stealth mode may block remote scans.\n\n" +
		"https://support.apple.com/HT207005\nSee the guide (https://example.com/a) and the rule.\n\n" +
		"NOTE: run \"defaults read x\".\n\n" +
		"- first\n- second\n\n" +
		"1. Go to System Settings\n2. Click Use Disk\n\n" +
		"sed 's/\\* file/x_y_z/' *.conf <<EOF\n^(?=.*[A-Z]).*$\nEOF"
	if got := asciidocText(in, "^(?=.*[A-Z]).*$"); got != want {
		t.Errorf("got:\n%s\n\nwant:\n%s", got, want)
	}
}

func TestRemediationListsProfileSettings(t *testing.T) {
	var r rule
	src := `
fix: |
  This is implemented by a Configuration Profile.
mobileconfig_info:
  com.apple.mobiledevice.passwordpolicy:
    minLength: $ODV
    customRegex:
      passwordContentRegex: "a.*b"
  com.apple.SubmitDiagInfo:
    AutoSubmit: false
ddm_info:
  declarationtype: com.apple.configuration.passcode.settings
  ddm_key: MinimumLength
  ddm_value: $ODV
`
	if err := yaml.Unmarshal([]byte(src), &r); err != nil {
		t.Fatal(err)
	}
	want := "This is implemented by a Configuration Profile.\n\n" +
		"Configuration profile settings (payload type: key = value):\n" +
		"com.apple.mobiledevice.passwordpolicy: minLength = 15\n" +
		"com.apple.mobiledevice.passwordpolicy: customRegex > passwordContentRegex = a.*b\n" +
		"com.apple.SubmitDiagInfo: AutoSubmit = false\n\n" +
		"With declarative device management instead: com.apple.configuration.passcode.settings: MinimumLength = 15"
	if got := remediation(r, "15"); got != want {
		t.Errorf("got:\n%s\n\nwant:\n%s", got, want)
	}
}
