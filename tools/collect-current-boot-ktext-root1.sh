#!/system/bin/sh
# collect-current-boot-ktext-root.sh
# Collect current same-boot canonical _text for IonStack CFI testing.
# Usage from adb shell:
#   sh /data/local/tmp/collect-current-boot-ktext-root.sh
# The script self-escalates with su, stores output under the script directory by default,
# temporarily relaxes kptr_restrict to 0, restores it on exit, and refuses zero _text.

SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo /data/local/tmp)"
OUTDIR="${OUTDIR:-${1:-$SCRIPT_DIR/ionstack-current-ktext}}"
ALLOW_KPTR_RELAXATION="${ALLOW_KPTR_RELAXATION:-1}"
KPTR_PATH="/proc/sys/kernel/kptr_restrict"
KPTR_BEFORE=""
KPTR_DURING=""
KPTR_CHANGED=0
OUT_FILE="$OUTDIR/current-ktext.txt"
ERR_FILE="$OUTDIR/current-ktext.err"

restore_kptr() {
    if [ "$KPTR_CHANGED" = "1" ] && [ -n "$KPTR_BEFORE" ]; then
        echo "$KPTR_BEFORE" > "$KPTR_PATH" 2>/dev/null || true
    fi
}
trap restore_kptr EXIT HUP INT TERM

shell_quote() {
    # Minimal single-quote escaping for Android sh.
    printf "%s" "$1" | sed "s/'/'\\''/g"
}

# Re-exec as root early. Keep OUTDIR explicitly so root writes into the same script-local folder.
if [ "$(id -u 2>/dev/null || echo 99999)" != "0" ]; then
    if ! command -v su >/dev/null 2>&1; then
        echo "status=FAILED"
        echo "reason=not_root_and_su_not_found"
        exit 1
    fi
    Q0=$(shell_quote "$0")
    QOUT=$(shell_quote "$OUTDIR")
    exec su -c "OUTDIR='$QOUT' ALLOW_KPTR_RELAXATION='$ALLOW_KPTR_RELAXATION' sh '$Q0'"
fi

fail() {
    reason="$1"
    mkdir -p "$OUTDIR" 2>/dev/null || true
    {
        echo "status=FAILED"
        echo "reason=$reason"
        echo "ts=$(date '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || date)"
        echo "uid=$(id 2>/dev/null)"
        echo "context=$(cat /proc/self/attr/current 2>/dev/null)"
        echo "outdir=$OUTDIR"
        echo "kptr_restrict_before=${KPTR_BEFORE:-unreadable}"
        echo "kptr_restrict_during=${KPTR_DURING:-unreadable}"
    } | tee "$ERR_FILE" >&2
    exit 1
}

mkdir -p "$OUTDIR" 2>/dev/null || fail "cannot_create_outdir:$OUTDIR"
: > "$OUT_FILE" 2>/dev/null || fail "cannot_write_out_file:$OUT_FILE"
: > "$ERR_FILE" 2>/dev/null || fail "cannot_write_err_file:$ERR_FILE"

BOOT_ID="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
[ -n "$BOOT_ID" ] || fail "cannot_read_boot_id"

# Relax kptr_restrict like the reference collector, but restore it on exit.
KPTR_BEFORE="$(cat "$KPTR_PATH" 2>/dev/null || true)"
if [ "$ALLOW_KPTR_RELAXATION" = "1" ] && [ -n "$KPTR_BEFORE" ] && [ "$KPTR_BEFORE" != "0" ]; then
    if echo 0 > "$KPTR_PATH" 2>/dev/null; then
        KPTR_CHANGED=1
    fi
fi
KPTR_DURING="$(cat "$KPTR_PATH" 2>/dev/null || true)"

# Dump kallsyms first; then all parsing uses the saved file for reproducibility.
cat /proc/kallsyms > "$OUTDIR/kallsyms.txt" 2>/dev/null || fail "cannot_read_kallsyms"
KALLSYMS_SIZE="$(wc -c < "$OUTDIR/kallsyms.txt" 2>/dev/null || echo 0)"
[ "$KALLSYMS_SIZE" != "0" ] || fail "empty_kallsyms"

# Save a focused key-symbol file for easy pullback.
grep -E '(^[0-9a-fA-F]+ [A-Za-z] (_text|_stext)$)| ashmem_fops$| sysctl_bootid$| loggers$| init_task$| root_task_group$| misc_fops$| anon_pipe_buf_ops$| selinux_enforcing$| security_hook_heads$' \
    "$OUTDIR/kallsyms.txt" > "$OUTDIR/key-symbols.txt" 2>/dev/null || true

sym_line() {
    sym="$1"
    awk -v s="$sym" '$3 == s { print; exit }' "$OUTDIR/kallsyms.txt" 2>/dev/null
}

addr_of() {
    line="$1"
    set -- $line
    printf "%s" "${1:-}"
}

is_zero_addr() {
    case "$1" in
        ""|0|0000000000000000|0x0000000000000000) return 0 ;;
        *) return 1 ;;
    esac
}

is_canonical_kernel_addr() {
    case "$1" in
        ffffff*|FFFFFF*) return 0 ;;
        *) return 1 ;;
    esac
}

TEXT_LINE="$(sym_line _text)"
STEXT_LINE="$(sym_line _stext)"
ASHMEM_FOPS_LINE="$(sym_line ashmem_fops)"
SYSCTL_BOOTID_LINE="$(sym_line sysctl_bootid)"
LOGGERS_LINE="$(sym_line loggers)"
INIT_TASK_LINE="$(sym_line init_task)"
ROOT_TG_LINE="$(sym_line root_task_group)"

TEXT_ADDR="$(addr_of "$TEXT_LINE")"
STEXT_ADDR="$(addr_of "$STEXT_LINE")"

if is_zero_addr "$TEXT_ADDR"; then
    fail "_text_missing_or_zero;root_context_hides_kernel_addresses;do_not_use_as_CFI_KASLR_BASE"
fi
if ! is_canonical_kernel_addr "$TEXT_ADDR"; then
    fail "_text_not_canonical:$TEXT_ADDR"
fi
if [ -n "$STEXT_ADDR" ] && ! is_zero_addr "$STEXT_ADDR" && ! is_canonical_kernel_addr "$STEXT_ADDR"; then
    fail "_stext_not_canonical:$STEXT_ADDR"
fi

{
    echo "status=OK"
    echo "ts=$(date '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || date)"
    echo "uid=$(id 2>/dev/null)"
    echo "context=$(cat /proc/self/attr/current 2>/dev/null)"
    echo "outdir=$OUTDIR"
    echo "boot_id=$BOOT_ID"
    echo "kptr_restrict_before=${KPTR_BEFORE:-unreadable}"
    echo "kptr_restrict_during=${KPTR_DURING:-unreadable}"
    echo "kptr_restrict_will_restore=$KPTR_CHANGED"
    echo "kallsyms_size=$KALLSYMS_SIZE"
    echo "kallsyms__text=$TEXT_LINE"
    echo "kallsyms__stext=$STEXT_LINE"
    echo "kallsyms_ashmem_fops=$ASHMEM_FOPS_LINE"
    echo "kallsyms_sysctl_bootid=$SYSCTL_BOOTID_LINE"
    echo "kallsyms_loggers=$LOGGERS_LINE"
    echo "kallsyms_init_task=$INIT_TASK_LINE"
    echo "kallsyms_root_task_group=$ROOT_TG_LINE"
    echo "CFI_KASLR_BASE=0x$TEXT_ADDR"
    echo "NOTE=Use this CFI_KASLR_BASE only while boot_id remains exactly $BOOT_ID."
} | tee "$OUT_FILE"

if [ ! -s "$OUT_FILE" ]; then
    fail "empty_current_ktext_output"
fi

# Optional archive and checksum, matching reference style.
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUTDIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum) > "$OUTDIR/SHA256SUMS" 2>/dev/null || true
fi
if command -v tar >/dev/null 2>&1; then
    tar -C "$(dirname "$OUTDIR")" -czf "$OUTDIR.tar.gz" "$(basename "$OUTDIR")" 2>/dev/null || true
fi

echo "OUTDIR=$OUTDIR"
echo "OUT_FILE=$OUT_FILE"
[ -f "$OUTDIR.tar.gz" ] && echo "ARCHIVE=$OUTDIR.tar.gz"
exit 0
