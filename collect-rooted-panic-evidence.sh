+#!/system/bin/sh
# IonStack / CVE-2026-43499 post-reboot evidence collector.
# Run this AFTER the rooted same-build device has rebooted from a reproduction.
# All output is created beside this script.

set -u
umask 077

SCRIPT_PATH="$0"
if command -v readlink >/dev/null 2>&1; then
  RESOLVED="$(readlink -f "$0" 2>/dev/null || true)"
  if [ -n "$RESOLVED" ]; then
    SCRIPT_PATH="$RESOLVED"
  fi
fi
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" 2>/dev/null && pwd)"
if [ -z "$SCRIPT_DIR" ]; then
  SCRIPT_DIR="$(pwd)"
fi

if [ "$(id -u)" != "0" ]; then
  echo "[*] Re-launching through su..."
  exec su -c "sh \"$SCRIPT_PATH\""
fi

STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown-time)"
OUT_DIR="$SCRIPT_DIR/ionstack-panic-evidence-$STAMP"
mkdir -p "$OUT_DIR/pstore" "$OUT_DIR/reboot" "$OUT_DIR/tombstones"

note() {
  printf '%s\n' "$*" | tee -a "$OUT_DIR/collector.log"
}

capture() {
  name="$1"
  shift
  {
    echo "===== $name ====="
    echo "command: $*"
    echo
    "$@"
  } > "$OUT_DIR/$name.txt" 2>&1 || true
}

copy_tree() {
  source_dir="$1"
  label="$2"
  target="$OUT_DIR/$label"
  if [ ! -d "$source_dir" ]; then
    return 0
  fi
  mkdir -p "$target"
  cp -a "$source_dir"/. "$target"/ 2>/dev/null || cp -R "$source_dir"/. "$target"/ 2>/dev/null || true
}

note "IonStack panic evidence collection started"
note "script_dir=$SCRIPT_DIR"
note "out_dir=$OUT_DIR"
note "uid=$(id -u)"

capture device-id id
capture uname uname -a
capture boot-id cat /proc/sys/kernel/random/boot_id
capture cmdline cat /proc/cmdline
capture build-props getprop
capture mount mount
capture dmesg dmesg
capture logcat-all logcat -b all -d -v threadtime
capture pstore-list sh -c 'ls -la /sys/fs/pstore 2>&1'
capture last-kmsg cat /proc/last_kmsg

if [ -d /sys/fs/pstore ]; then
  find /sys/fs/pstore -type f 2>/dev/null | while IFS= read -r f; do
    base="$(basename "$f")"
    cat "$f" > "$OUT_DIR/pstore/$base" 2>&1 || true
  done
fi

# Xiaomi/Android reboot diagnostics; paths vary by build.
copy_tree /data/miuilog/stability/reboot reboot/miui-reboot
copy_tree /data/misc/prereboot reboot/prereboot
copy_tree /data/tombstones tombstones/data
copy_tree /data/vendor/tombstones tombstones/vendor
copy_tree /sys/fs/pstore pstore/raw-copy

capture relevant-kernel-log sh -c 'dmesg 2>/dev/null | grep -Ei "panic|fatal|oops|BUG:|rt_mutex|sched_setattr|watchdog|rb_erase|Call trace" || true'

(
  cd "$OUT_DIR" || exit 0
  find . -type f -maxdepth 4 -print0 2>/dev/null | sort -z | xargs -0 sha256sum 2>/dev/null > SHA256SUMS.txt || true
)

ARCHIVE="$SCRIPT_DIR/ionstack-panic-evidence-$STAMP.tar.gz"
if command -v tar >/dev/null 2>&1; then
  (
    cd "$SCRIPT_DIR" || exit 0
    tar -czf "$ARCHIVE" "$(basename "$OUT_DIR")" 2>/dev/null || true
  )
fi

note "Collection complete."
note "directory=$OUT_DIR"
[ -f "$ARCHIVE" ] && note "archive=$ARCHIVE"

