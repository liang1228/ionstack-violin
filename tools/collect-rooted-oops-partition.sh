#!/system/bin/sh
# Extract Xiaomi mtdoops persistence evidence after a test-device reboot.
# Run this on the rooted same-build device *after* a controlled reproduction.
# It is read-only: it never writes the oops partition or alters logging state.

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
  echo "[ionstack] re-launching through su..."
  exec su -c "sh \"$SCRIPT_PATH\""
fi

STAMP="$(date +%Y%m%d-%H%M%S 2>/dev/null || echo unknown-time)"
OUT_DIR="$SCRIPT_DIR/ionstack-oops-partition-$STAMP"
mkdir -p "$OUT_DIR"
RECORD_SIZE=1048576

note() { printf '%s\n' "$*" | tee -a "$OUT_DIR/collector.log"; }
capture() {
  name="$1"; shift
  { echo "===== $name ====="; echo "command: $*"; echo; "$@"; } > "$OUT_DIR/$name.txt" 2>&1 || true
}

note "[ionstack] mtdoops collection started"
capture device-id id
capture boot-id cat /proc/sys/kernel/random/boot_id
capture cmdline cat /proc/cmdline
capture partitions sh -c 'ls -l /dev/block/by-name/oops /dev/block/bootdevice/by-name/oops 2>&1; cat /proc/partitions 2>&1'
capture pstore-list sh -c 'ls -la /sys/fs/pstore 2>&1'

# The oops record and these symbols must belong to the same boot.  Some rooted
# contexts still have kptr_restrict enabled, so lower it only while capturing
# and restore the original value before continuing.
KPTR_FILE=/proc/sys/kernel/kptr_restrict
KPTR_ORIGINAL=""
if [ -r "$KPTR_FILE" ]; then
  KPTR_ORIGINAL="$(cat "$KPTR_FILE" 2>/dev/null || true)"
fi
if [ -n "$KPTR_ORIGINAL" ] && [ -w "$KPTR_FILE" ]; then
  printf '0\n' > "$KPTR_FILE" 2>"$OUT_DIR/kptr-restrict-set.stderr" || true
fi
capture kptr-restrict-before-restore cat "$KPTR_FILE"
capture canonical-kallsyms sh -c 'grep -E "_text$|_stext$|init_task |nfulnl_logger|loggers |sysctl_bootid|root_task_group|misc_fops|ashmem_fops|anon_pipe_buf_ops|KASLR|vmalloc" /proc/kallsyms'
CANONICAL_LINES="$(grep -Ec '^ffff[^[:space:]]*[[:space:]]' "$OUT_DIR/canonical-kallsyms.txt" 2>/dev/null || true)"
[ -n "$CANONICAL_LINES" ] || CANONICAL_LINES=0
printf 'canonical_symbol_lines=%s\n' "$CANONICAL_LINES" > "$OUT_DIR/canonical-kallsyms-status.txt"
if [ "$CANONICAL_LINES" -eq 0 ]; then
  note "[ionstack] WARNING: kallsyms capture contains no canonical addresses; raw oops evidence remains valid."
else
  note "[ionstack] canonical kallsyms verified: $CANONICAL_LINES symbol lines"
fi
if [ -n "$KPTR_ORIGINAL" ] && [ -w "$KPTR_FILE" ]; then
  printf '%s\n' "$KPTR_ORIGINAL" > "$KPTR_FILE" 2>"$OUT_DIR/kptr-restrict-restore.stderr" || true
fi
capture kptr-restrict-restored cat "$KPTR_FILE"

OOPS_DEV=""
for candidate in /dev/block/by-name/oops /dev/block/bootdevice/by-name/oops; do
  if [ -e "$candidate" ]; then OOPS_DEV="$candidate"; break; fi
done

if [ -z "$OOPS_DEV" ]; then
  note "[ionstack] ERROR: no oops partition path found; saved metadata only."
  printf 'RESULT=FAILED\nREASON=oops partition path not found\n' > "$OUT_DIR/EVIDENCE_STATUS.txt"
else
  OOPS_REAL="$OOPS_DEV"
  if command -v readlink >/dev/null 2>&1; then
    RESOLVED_DEV="$(readlink -f "$OOPS_DEV" 2>/dev/null || true)"
    [ -n "$RESOLVED_DEV" ] && OOPS_REAL="$RESOLVED_DEV"
  fi
  note "[ionstack] reading one configured mtdoops record from $OOPS_DEV ($OOPS_REAL)"
  if [ ! -b "$OOPS_REAL" ]; then
    note "[ionstack] ERROR: resolved oops path is not a block device"
    printf 'RESULT=FAILED\nREASON=resolved path is not a block device\nPATH=%s\n' "$OOPS_REAL" > "$OUT_DIR/EVIDENCE_STATUS.txt"
  else
    # cmdline config is record_size=1048576. Read exactly one record, never write it.
    dd if="$OOPS_REAL" of="$OUT_DIR/oops-record.bin" bs="$RECORD_SIZE" count=1 2>"$OUT_DIR/dd.stderr"
    DD_RC=$?
    BYTES="$(wc -c < "$OUT_DIR/oops-record.bin" 2>/dev/null | tr -d '[:space:]')"
    [ -n "$BYTES" ] || BYTES=0
    printf 'device=%s\nresolved_device=%s\ndd_exit=%s\nexpected_bytes=%s\nactual_bytes=%s\n' \
      "$OOPS_DEV" "$OOPS_REAL" "$DD_RC" "$RECORD_SIZE" "$BYTES" > "$OUT_DIR/read-result.txt"
    if [ "$DD_RC" -ne 0 ] || [ "$BYTES" -ne "$RECORD_SIZE" ]; then
      note "[ionstack] ERROR: oops record read is invalid (dd=$DD_RC bytes=$BYTES expected=$RECORD_SIZE)"
      printf 'RESULT=FAILED\nREASON=dd did not return one full record\n' > "$OUT_DIR/EVIDENCE_STATUS.txt"
      rm -f "$OUT_DIR/oops-record.bin"
    else
      note "[ionstack] verified non-empty raw record: $BYTES bytes"
      printf 'RESULT=OK\nRECORD_BYTES=%s\nSOURCE=%s\n' "$BYTES" "$OOPS_REAL" > "$OUT_DIR/EVIDENCE_STATUS.txt"
      sha256sum "$OUT_DIR/oops-record.bin" > "$OUT_DIR/oops-record.sha256" 2>&1 || true
      if command -v strings >/dev/null 2>&1; then
        strings -a "$OUT_DIR/oops-record.bin" > "$OUT_DIR/oops-record.strings.txt" 2>&1 || true
      elif command -v toybox >/dev/null 2>&1; then
        toybox strings -a "$OUT_DIR/oops-record.bin" > "$OUT_DIR/oops-record.strings.txt" 2>&1 || true
      else
        note "[ionstack] strings utility unavailable; raw record retained."
      fi
      {
        echo '===== matching lines ====='
        grep -Ein 'panic|fatal|oops|BUG:|rt_mutex|sched_setattr|rb_erase|Call trace|SLIDE' "$OUT_DIR/oops-record.strings.txt" 2>&1 || true
      } > "$OUT_DIR/oops-record-interesting.txt"
    fi
  fi
fi

if [ -d /sys/fs/pstore ]; then
  mkdir -p "$OUT_DIR/pstore"
  find /sys/fs/pstore -type f 2>/dev/null | while IFS= read -r f; do
    cat "$f" > "$OUT_DIR/pstore/$(basename "$f")" 2>&1 || true
  done
fi

( cd "$OUT_DIR" && find . -type f -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS.txt 2>/dev/null ) || true
ARCHIVE="$SCRIPT_DIR/ionstack-oops-partition-$STAMP.tar.gz"
if command -v tar >/dev/null 2>&1; then
  ( cd "$SCRIPT_DIR" && tar -czf "$ARCHIVE" "$(basename "$OUT_DIR")" ) 2>/dev/null || true
fi
note "[ionstack] complete: $OUT_DIR"
[ -f "$ARCHIVE" ] && note "[ionstack] archive: $ARCHIVE"
