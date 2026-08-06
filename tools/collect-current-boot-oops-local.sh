#!/system/bin/sh
# Android local-terminal collector for the current boot's mtdoops record.
# Read-only: self-elevates with su, reads exactly one record, restores kptr
# settings, then leaves a pullable tar.gz under /sdcard/Download by default.

set -u
umask 077

SCRIPT_PATH="$0"
if command -v readlink >/dev/null 2>&1; then
  resolved="$(readlink -f "$0" 2>/dev/null || true)"
  [ -n "$resolved" ] && SCRIPT_PATH="$resolved"
fi

shell_quote() { printf '%s' "$1" | sed "s/'/'\\''/g"; }
OUT_BASE="${OUT_BASE:-/sdcard/Download}"

if [ "$(id -u 2>/dev/null || echo 99999)" != "0" ]; then
  command -v su >/dev/null 2>&1 || {
    echo '[ionstack] ERROR: root is required but su is unavailable' >&2
    exit 1
  }
  echo '[ionstack] requesting root via su...'
  q_script="$(shell_quote "$SCRIPT_PATH")"
  q_out="$(shell_quote "$OUT_BASE")"
  exec su -c "OUT_BASE='$q_out' sh '$q_script'"
fi

STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown-time)"
OUT_DIR="$OUT_BASE/ionstack-oops-currentboot-$STAMP"
ARCHIVE="$OUT_BASE/ionstack-oops-currentboot-$STAMP.tar.gz"
RECORD_SIZE=1048576
mkdir -p "$OUT_DIR" || exit 1

note() { printf '%s\n' "$*" | tee -a "$OUT_DIR/collector.log"; }
capture() { name="$1"; shift; { echo "===== $name ====="; "$@"; } > "$OUT_DIR/$name.txt" 2>&1 || true; }

note '[ionstack] current-boot oops collection started (read-only)'
capture id id
capture boot-id cat /proc/sys/kernel/random/boot_id
capture cmdline cat /proc/cmdline
capture partitions sh -c 'ls -l /dev/block/by-name/oops /dev/block/bootdevice/by-name/oops 2>&1; cat /proc/partitions 2>&1'

KPTR=/proc/sys/kernel/kptr_restrict
KPTR_OLD="$(cat "$KPTR" 2>/dev/null || true)"
restore_kptr() { [ -n "$KPTR_OLD" ] && printf '%s\n' "$KPTR_OLD" > "$KPTR" 2>/dev/null || true; }
trap restore_kptr EXIT HUP INT TERM
[ -n "$KPTR_OLD" ] && printf '0\n' > "$KPTR" 2>/dev/null || true
capture kallsyms sh -c 'grep -E " (_text|_stext|worker_thread|init_cred|init_task|loggers|sysctl_bootid)$" /proc/kallsyms'

OOPS=""
for p in /dev/block/by-name/oops /dev/block/bootdevice/by-name/oops; do
  [ -e "$p" ] && { OOPS="$p"; break; }
done
if [ -z "$OOPS" ]; then
  printf 'RESULT=FAILED\nREASON=oops_partition_missing\n' > "$OUT_DIR/EVIDENCE_STATUS.txt"
  note '[ionstack] ERROR: oops partition missing'
else
  REAL="$(readlink -f "$OOPS" 2>/dev/null || printf '%s' "$OOPS")"
  if [ ! -b "$REAL" ]; then
    printf 'RESULT=FAILED\nREASON=oops_not_block_device\nPATH=%s\n' "$REAL" > "$OUT_DIR/EVIDENCE_STATUS.txt"
  else
    dd if="$REAL" of="$OUT_DIR/oops-record.bin" bs="$RECORD_SIZE" count=1 2>"$OUT_DIR/dd.stderr"
    rc=$?
    bytes="$(wc -c < "$OUT_DIR/oops-record.bin" 2>/dev/null | tr -d '[:space:]')"
    [ -n "$bytes" ] || bytes=0
    printf 'source=%s\nresolved=%s\ndd_exit=%s\nexpected_bytes=%s\nactual_bytes=%s\n' "$OOPS" "$REAL" "$rc" "$RECORD_SIZE" "$bytes" > "$OUT_DIR/read-result.txt"
    if [ "$rc" -ne 0 ] || [ "$bytes" -ne "$RECORD_SIZE" ]; then
      rm -f "$OUT_DIR/oops-record.bin"
      printf 'RESULT=FAILED\nREASON=short_or_failed_read\n' > "$OUT_DIR/EVIDENCE_STATUS.txt"
    else
      sha256sum "$OUT_DIR/oops-record.bin" > "$OUT_DIR/oops-record.sha256" 2>&1 || true
      (strings -a "$OUT_DIR/oops-record.bin" 2>/dev/null || toybox strings -a "$OUT_DIR/oops-record.bin" 2>/dev/null || true) > "$OUT_DIR/oops-record.strings.txt"
      grep -Ein 'panic|fatal|oops|BUG:|rt_mutex|sched_setattr|rb_erase|Call trace|FOPSROUTE|CFI_' "$OUT_DIR/oops-record.strings.txt" > "$OUT_DIR/oops-interesting.txt" 2>&1 || true
      printf 'RESULT=OK\nRECORD_BYTES=%s\nSOURCE=%s\n' "$bytes" "$REAL" > "$OUT_DIR/EVIDENCE_STATUS.txt"
    fi
  fi
fi

restore_kptr
trap - EXIT HUP INT TERM
(cd "$OUT_DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt) 2>/dev/null || true
tar -C "$OUT_BASE" -czf "$ARCHIVE" "$(basename "$OUT_DIR")" 2>/dev/null || true
note "[ionstack] OUTDIR=$OUT_DIR"
[ -f "$ARCHIVE" ] && note "[ionstack] ARCHIVE=$ARCHIVE"
