package syslog

import (
	"bufio"
	"net"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestUDPRFC5424(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no UDP:", err)
	}
	defer pc.Close()
	w, err := Dial("udp://"+pc.LocalAddr().String()+"?facility=local3", "checkmate")
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Send(Warning, "result", `{"id":"X"}`); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^<156>1 \d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z \S+ checkmate \d+ result - \{"id":"X"\}$`)
	if !re.Match(buf[:n]) {
		t.Errorf("unexpected message %q", buf[:n])
	}
}

func TestTCPOctetCounting(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no TCP:", err)
	}
	defer ln.Close()
	got := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		var msgs []string
		for i := 0; i < 2; i++ {
			lenStr, err := r.ReadString(' ')
			if err != nil {
				break
			}
			n, _ := strconv.Atoi(strings.TrimSpace(lenStr))
			b := make([]byte, n)
			if _, err := r.Read(b); err != nil {
				break
			}
			msgs = append(msgs, string(b))
		}
		got <- msgs
	}()
	w, err := Dial("tcp://"+ln.Addr().String(), "checkmate")
	if err != nil {
		t.Fatal(err)
	}
	w.Send(Info, "result", "first")
	w.Send(Notice, "summary", "second message")
	w.Close()
	msgs := <-got
	if len(msgs) != 2 || !strings.HasPrefix(msgs[0], "<14>1 ") || !strings.HasSuffix(msgs[1], "summary - second message") {
		t.Errorf("unexpected frames %q", msgs)
	}
}

func TestDialErrors(t *testing.T) {
	for _, target := range []string{"udp://host?facility=nope", "http://host", "udp://", "local?x=%zz"} {
		if _, err := Dial(target, "checkmate"); err == nil {
			t.Errorf("%s: expected an error", target)
		}
	}
}
