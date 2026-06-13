pid=$(pgrep -x wakora)
r0=$(awk '/read_bytes/{print $2}' /proc/$pid/io)
fd0=$(ls -l /proc/$pid/fd 2>/dev/null | grep -oE '/var/log[^ ]*|/www[^ ]*' | sort | md5sum | cut -c1-12)
nfd0=$(ls -l /proc/$pid/fd 2>/dev/null | grep -cE '/var/log|/www')
sleep 90
r1=$(awk '/read_bytes/{print $2}' /proc/$pid/io)
fd1=$(ls -l /proc/$pid/fd 2>/dev/null | grep -oE '/var/log[^ ]*|/www[^ ]*' | sort | md5sum | cut -c1-12)
echo "version: $(/usr/local/bin/wakora --version)"
echo "read_bytes/90s: $(( (r1 - r0) / 1024 )) KB"
echo "log fds: $nfd0  fdset t0=$fd0 t1=$fd1  stable=$([ "$fd0" = "$fd1" ] && echo YES || echo NO)"
