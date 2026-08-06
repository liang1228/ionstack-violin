#!/system/bin/sh
set -eu

# Run on the rooted device while the target process is still in the same boot.
# The module is observational: it does not invoke the target or alter fdsets.
MOD="${1:?usage: $0 /data/local/tmp/ionstack_kprobe_oracle.ko TARGET_TGID [output]}"
TGID="${2:?missing target TGID}"
OUT="${3:-/data/local/tmp/ionstack-kprobe-oracle.txt}"
SHIFT="${PSELECT_WAITER_WORD_SHIFT:-0}"

su -c "rmmod ionstack_kprobe_oracle 2>/dev/null || true; insmod '$MOD' target_tgid='$TGID' pselect_waiter_word_shift='$SHIFT'"
trap 'su -c "rmmod ionstack_kprobe_oracle 2>/dev/null || true"' EXIT HUP INT TERM
test -r /proc/ionstack_oracle
su -c "cat /proc/ionstack_oracle" | tee "$OUT"
echo "OUT=$OUT"
