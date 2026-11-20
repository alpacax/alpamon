FROM ubuntu:24.04
ENV container=docker
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y systemd systemd-sysv dbus passwd rsyslog && rm -rf /var/lib/apt/lists/*
CMD ["/sbin/init"]
