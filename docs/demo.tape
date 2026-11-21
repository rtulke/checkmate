# Terminal demo for the README and the documentation, rendered with vhs
# (https://github.com/charmbracelet/vhs):
#
#     vhs docs/demo.tape          # -> docs/assets/demo.gif
#
# Run it from the repository root on a machine with Go and Docker. The demo
# runs inside a Debian container with the host name "web-01", so it looks
# the same everywhere and never shows the name of the rendering machine.
# docs/demo/setup.sh creates the files the demo policy checks; everything
# else the demo shows is real checkmate output.

Output docs/assets/demo.gif

Set Shell bash
Set FontSize 14
Set Width 1200
Set Height 820
Set Padding 18
Set Margin 20
Set MarginFill "#2A2833"
Set BorderRadius 10
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Env LC_ALL "C.UTF-8"

# --- setup, not shown -------------------------------------------------------
Hide
Type "GOOS=linux GOARCH=$(go env GOARCH) CGO_ENABLED=0 go build -o bin/checkmate-linux ./cmd/checkmate" Enter
Type "docker build -q -t checkmate-test:debian12 -f test/linux/debian12.Dockerfile test/linux >/dev/null" Enter
Type "docker run --rm -it --hostname web-01 -e PS1='$ ' -e TERM=xterm-256color -v $PWD:/src -w /src/docs/demo checkmate-test:debian12 bash --norc" Enter
Sleep 3s
Type "ln -sf /src/bin/checkmate-linux /usr/local/bin/checkmate && sh setup.sh && clear" Enter
Sleep 1s
Show

# --- the demo ---------------------------------------------------------------
Type "cat demo.yml" Sleep 300ms Enter
Sleep 7s

Hide
Type "clear" Enter
Show
Type "checkmate run demo.yml" Sleep 300ms Enter
Sleep 7s

Hide
Type "clear" Enter
Show
Type "sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /tmp/checkmate-demo/sshd_config" Sleep 300ms Enter
Sleep 1s
Type "checkmate run demo.yml --fail-on high" Sleep 300ms Enter
Sleep 7s

Hide
Type "clear" Enter
Show
Type "checkmate list -v demo.yml --id 'SVC-*'" Sleep 300ms Enter
Sleep 5s

Hide
Type "clear" Enter
Show
Type "checkmate run demo.yml --format json | jq .summary" Sleep 300ms Enter
Sleep 6s

# --- cleanup, not shown -----------------------------------------------------
Hide
Type "exit" Enter
Sleep 1s
