// Package syslog sends messages to the local syslog daemon or to a remote
// collector over UDP, TCP or TLS.
//
// Local messages use the traditional BSD format (RFC 3164) that every local
// daemon, journald included, understands. Remote messages use RFC 5424;
// over TCP and TLS they are framed by octet counting (RFC 6587, RFC 5425).
package syslog

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

// Severities (RFC 5424).
const (
	Emergency = iota
	Alert
	Critical
	Error
	Warning
	Notice
	Info
	Debug
)

var facilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
	"uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, "local0": 16, "local1": 17, "local2": 18,
	"local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// Writer sends syslog messages.
type Writer struct {
	conn     net.Conn
	local    bool
	stream   bool // TCP or TLS: octet-counting framing
	facility int
	tag      string
	hostname string
	pid      int
}

// localSockets are the paths of the local syslog socket on Linux, macOS
// and the BSDs.
var localSockets = []string{"/dev/log", "/var/run/syslog", "/var/run/log"}

// Dial connects to a target: "local" (or empty) for the local daemon, or a
// URL udp://host[:port], tcp://host[:port] or tls://host[:port]. A
// "facility" query parameter selects the facility (default: user), e.g.
// udp://siem.example.com?facility=local3.
func Dial(target, tag string) (*Writer, error) {
	w := &Writer{facility: facilities["user"], tag: tag, pid: os.Getpid()}
	w.hostname, _ = os.Hostname()
	if target == "" {
		target = "local"
	}
	var query url.Values
	if i := strings.IndexByte(target, '?'); i >= 0 {
		var err error
		if query, err = url.ParseQuery(target[i+1:]); err != nil {
			return nil, fmt.Errorf("syslog target %q: %v", target, err)
		}
		target = target[:i]
	}
	if f := query.Get("facility"); f != "" {
		n, ok := facilities[f]
		if !ok {
			return nil, fmt.Errorf("unknown syslog facility %q", f)
		}
		w.facility = n
	}

	if target == "local" {
		if runtime.GOOS == "windows" {
			return nil, errors.New("there is no local syslog on Windows; use udp://, tcp:// or tls://host")
		}
		w.local = true
		var lastErr error
		for _, path := range localSockets {
			for _, network := range []string{"unixgram", "unix"} {
				conn, err := net.Dial(network, path)
				if err == nil {
					w.conn, w.stream = conn, network == "unix"
					return w, nil
				}
				lastErr = err
			}
		}
		return nil, fmt.Errorf("no local syslog socket found: %v", lastErr)
	}

	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid syslog target %q (use local, udp://host, tcp://host or tls://host)", target)
	}
	host := u.Host
	if u.Port() == "" {
		port := "514"
		if u.Scheme == "tls" {
			port = "6514"
		}
		host = net.JoinHostPort(u.Hostname(), port)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	switch u.Scheme {
	case "udp":
		w.conn, err = dialer.Dial("udp", host)
	case "tcp":
		w.conn, err = dialer.Dial("tcp", host)
		w.stream = true
	case "tls":
		w.conn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		w.stream = true
	default:
		return nil, fmt.Errorf("unsupported syslog scheme %q (use udp, tcp or tls)", u.Scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("syslog %s: %v", target, err)
	}
	return w, nil
}

// Send writes one message. msgID is used by RFC 5424 only.
func (w *Writer) Send(severity int, msgID, msg string) error {
	pri := w.facility*8 + severity
	now := time.Now()
	var line string
	if w.local {
		line = fmt.Sprintf("<%d>%s %s[%d]: %s", pri, now.Format(time.Stamp), w.tag, w.pid, msg)
	} else {
		line = fmt.Sprintf("<%d>1 %s %s %s %d %s - %s", pri, now.UTC().Format("2006-01-02T15:04:05.000Z"),
			nilValue(w.hostname), w.tag, w.pid, nilValue(msgID), msg)
	}
	if w.stream {
		if w.local {
			line += "\n"
		} else {
			line = fmt.Sprintf("%d %s", len(line), line)
		}
	}
	w.conn.SetWriteDeadline(now.Add(10 * time.Second))
	_, err := w.conn.Write([]byte(line))
	return err
}

// Close closes the connection.
func (w *Writer) Close() error { return w.conn.Close() }

func nilValue(s string) string {
	s = strings.Map(func(r rune) rune {
		if r <= ' ' || r > '~' {
			return -1
		}
		return r
	}, s)
	if s == "" {
		return "-"
	}
	return s
}
