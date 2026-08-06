#!/system/bin/sh
echo PRELOAD_CMD_START
id
getenforce
rm -rf /data/local/tmp/dump
rc=$?
echo cleanup_rc=$rc
if [ "$rc" -eq 0 ]; then
  umask 077
  : > /data/local/tmp/dump
  grc=$?
  if [ "$grc" -eq 0 ]; then
    chmod 000 /data/local/tmp/dump
    grc=$?
  fi
  echo guard_create_rc=$grc
fi
ls -ld /data/local/tmp/dump 2>&1
df -k /data/local/tmp
echo PRELOAD_CMD_END
exit "$rc"
