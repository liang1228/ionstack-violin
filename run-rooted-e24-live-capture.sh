+#!/system/bin/sh
# Start a rooted same-build E24 reproduction while preserving live kernel logs.
# The device may reboot. After it boots, run collect-rooted-panic-evidence.sh
# from this same directory and send both the live log and the archive.

set -u
umask 077

SCRIPT_PATH="$0"
if command -v readlink >/dev/null 2>&1; then
  RESOLVED="$(readlink -f "$0" 2>/dev/null || true)"
  [ -n "$RESOLVED" ] && SCRIPT_PATH="$RESOLVED"
fi
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" 2>/dev/null && pwd)"
[ -n "$SCRIPT_DIR" ] || SCRIPT_DIR="$(pwd)"

if [ "$(id -u)" != "0" ]; then
  exec su -c "sh \"$SCRIPT_PATH\""
fi

STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown-time)"
OUT_DIR="$SCRIPT_DIR/ionstack-e24-live-$STAMP"
mkdir -p "$OUT_DIR"
KMSG="$OUT_DIR/live-dmesg.txt"
LOGCAT="$OUT_DIR/live-kernel-logcat.txt"
URL="https://liang1228.github.io/ionstack-violin/index.html?payload=e24&v=2d5d3ef"

printf '%s\n' "started=$STAMP" > "$OUT_DIR/metadata.txt"
printf '%s\n' "url=$URL" >> "$OUT_DIR/metadata.txt"
printf '%s\n' "uid=$(id -u)" >> "$OUT_DIR/metadata.txt"
uname -a >> "$OUT_DIR/metadata.txt" 2>&1 || true
cat /proc/sys/kernel/random/boot_id >> "$OUT_DIR/metadata.txt" 2>&1 || true

# Keep both streams in regular shared-storage files. They survive a kernel reset
# even though these background processes do not.
dmesg -w > "$KMSG" 2>&1 &
KMSG_PID=$!
logcat -b kernel -v threadtime > "$LOGCAT" 2>&1 &
LOGCAT_PID=$!
printf '%s\n' "dmesg_pid=$KMSG_PID" >> "$OUT_DIR/metadata.txt"
printf '%s\n' "logcat_pid=$LOGCAT_PID" >> "$OUT_DIR/metadata.txt"
sync

sleep 2
am force-stop --user 0 org.mozilla.firefox >/dev/null 2>&1 || true
am start -S --user 0   -n org.mozilla.firefox/org.mozilla.fenix.IntentReceiverActivity   -a android.intent.action.VIEW -d "$URL"   > "$OUT_DIR/launch.txt" 2>&1 || true
sync

echo "E24 launched. If the device resets, do not delete $OUT_DIR."
echo "After boot, run collect-rooted-panic-evidence.sh beside this script."

