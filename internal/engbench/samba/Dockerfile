# Samba 4.22 on debian:trixie, the reference server of the engine comparison.
# /run/pw holds "password\npassword\n" (mounted, never an argument); /data is
# the share; smb.conf is mounted over /etc/samba/smb.conf.
FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends samba procps && rm -rf /var/lib/apt/lists/*
RUN useradd -M -s /usr/sbin/nologin alice
EXPOSE 445
CMD ["sh", "-c", "smbpasswd -a -s alice < /run/pw && exec smbd --foreground --no-process-group --debug-stdout"]
