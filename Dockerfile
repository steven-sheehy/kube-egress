FROM alpine:latest
MAINTAINER Steven Sheehy <ssheehy@firescope.com>
RUN apk -U add bash dumb-init iproute2 iptables
COPY egress.sh /usr/bin/
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/usr/bin/egress.sh"]

