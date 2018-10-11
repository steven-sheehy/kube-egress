FROM alpine:latest
MAINTAINER Steven Sheehy <ssheehy@firescope.com>
RUN apk -U add bash iproute2 iptables
COPY egress.sh /usr/bin/
ENTRYPOINT ["/usr/bin/egress.sh"]

