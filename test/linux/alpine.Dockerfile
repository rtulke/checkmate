FROM alpine:3.20
# busybox provides awk, sed, grep and find here: the strictest test.
RUN apk add --no-cache bash openssh-server sudo openssl curl jq && ssh-keygen -A
