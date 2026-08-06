#!/system/bin/sh
# MT 管理器：把本脚本放到任意目录，然后使用 Root 终端执行：
#   su -c 'sh /sdcard/Download/collect-rooted-baseline.sh'
# 完成后压缩包和 SHA-256 文件会直接生成在脚本所在目录。
set -u

case "$0" in
  /*) SCRIPT_PATH="$0" ;;
  *)  SCRIPT_PATH="$PWD/$0" ;;
esac
SCRIPT_DIR="$(CDPATH= cd "$(dirname "$SCRIPT_PATH")" 2>/dev/null && pwd)"
[ -n "$SCRIPT_DIR" ] || SCRIPT_DIR="$PWD"

OUT="$SCRIPT_DIR/violin-kernel-evidence-work"
PUB="$SCRIPT_DIR/violin-kernel-evidence.tar.gz"
PUB_SHA="$SCRIPT_DIR/violin-kernel-evidence.tar.gz.sha256"
rm -rf "$OUT"
rm -f "$PUB" "$PUB_SHA"
mkdir -p "$OUT" "$OUT/proc" "$OUT/sys" "$OUT/pstore" "$OUT/partitions" "$OUT/modules"

run() { "$@" >"$2" 2>&1 || true; }
copy() { [ -e "$1" ] && cp -a "$1" "$2" 2>/dev/null || true; }

{
  date -u
  id
  uname -a
  getprop ro.product.device
  getprop ro.product.model
  getprop ro.build.fingerprint
  getprop ro.build.version.incremental
  getprop ro.build.version.security_patch
  getprop ro.boot.slot_suffix
  getprop ro.boot.verifiedbootstate
  getprop ro.boot.vbmeta.digest
  cat /proc/sys/kernel/random/boot_id
} > "$OUT/device.txt" 2>&1

getprop > "$OUT/getprop.txt" 2>&1 || true
cat /proc/version > "$OUT/proc/version" 2>&1 || true
cat /proc/cmdline > "$OUT/proc/cmdline" 2>&1 || true
cat /proc/bootconfig > "$OUT/proc/bootconfig" 2>&1 || true
cat /proc/config.gz > "$OUT/proc/config.gz" 2>/dev/null || true
cat /proc/kallsyms > "$OUT/proc/kallsyms" 2>/dev/null || true
cat /proc/iomem > "$OUT/proc/iomem" 2>/dev/null || true
cat /proc/slabinfo > "$OUT/proc/slabinfo" 2>/dev/null || true
cat /proc/modules > "$OUT/proc/modules" 2>/dev/null || true
cat /proc/meminfo > "$OUT/proc/meminfo" 2>/dev/null || true
cat /proc/zoneinfo > "$OUT/proc/zoneinfo" 2>/dev/null || true
cat /proc/vmallocinfo > "$OUT/proc/vmallocinfo" 2>/dev/null || true

copy /sys/kernel/btf/vmlinux "$OUT/sys/vmlinux.btf"
copy /sys/kernel/kheaders.tar.xz "$OUT/sys/kheaders.tar.xz"
copy /sys/fs/selinux/policy "$OUT/sys/selinux-policy"
cp -a /sys/fs/pstore/. "$OUT/pstore/" 2>/dev/null || true

# Device tree controls memory layout and reserved-memory/direct-map assumptions.
tar -czf "$OUT/sys/device-tree.tar.gz" -C /sys/firmware devicetree/base 2>/dev/null || true

# Module BTF and module binaries are useful for type/symbol cross-checks.
tar -czf "$OUT/sys/module-btf.tar.gz" -C /sys/kernel btf 2>/dev/null || true
for d in /vendor_dlkm/lib/modules /system_dlkm/lib/modules /vendor/lib/modules; do
  [ -d "$d" ] || continue
  label="$(echo "$d" | tr '/' '_' | sed 's/^_//')"
  tar -czf "$OUT/modules/$label.tar.gz" -C "$d" . 2>/dev/null || true
done

# Exact running boot-chain images. Avoid super/userdata dumps.
SLOT="$(getprop ro.boot.slot_suffix)"
for name in boot init_boot vendor_boot vendor_kernel_boot dtbo vbmeta vbmeta_system vbmeta_vendor; do
  src="/dev/block/by-name/${name}${SLOT}"
  [ -e "$src" ] || src="/dev/block/by-name/$name"
  [ -e "$src" ] && dd if="$src" of="$OUT/partitions/$name.img" bs=4M 2>/dev/null || true
done

# Preserve last-kmsg alternatives where vendors expose them outside pstore.
for f in /proc/last_kmsg /sys/kernel/debug/dmesg_last /data/vendor/ramoops/console-ramoops; do
  [ -e "$f" ] && cp -a "$f" "$OUT/pstore/$(echo "$f" | tr '/' '_')" 2>/dev/null || true
done
dmesg -T > "$OUT/pstore/dmesg-current.txt" 2>&1 || dmesg > "$OUT/pstore/dmesg-current.txt" 2>&1 || true

find "$OUT" -type f -exec sha256sum {} \; > "$OUT/SHA256SUMS" 2>/dev/null || true
tar -czf "$PUB" -C "$(dirname "$OUT")" "$(basename "$OUT")"
chmod 0644 "$PUB"
sha256sum "$PUB" > "$PUB_SHA" 2>/dev/null || true
chmod 0644 "$PUB_SHA" 2>/dev/null || true
sync
echo "COLLECTION_COMPLETE"
echo "Archive: $PUB"
echo "SHA256: $PUB_SHA"
ls -lh "$PUB" "$PUB_SHA" 2>/dev/null || true
