#!/bin/bash
# Build GKI kernel for Xiaomi Pad 7S Pro (violin-v-oss) to get System.map
# Run this in WSL Ubuntu

set -e

WORK_DIR="/mnt/e/workspace/projects/xiaomi-root"
KERNEL_SRC="$WORK_DIR/kernel-src-wsl"
NDK_DIR="$HOME/android-ndk"
BUILD_DIR="$KERNEL_SRC/common-gki/out"

echo "=========================================="
echo "Building GKI kernel for violin (6.6.77)"
echo "=========================================="

# Step 1: Install dependencies
echo "[1/6] Installing build dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    build-essential flex bison libssl-dev libelf-dev bc \
    python3 python3-pip cpio kmod libncurses-dev \
    git curl wget zip unzip 2>&1 | tail -3

# Step 2: Clone kernel source
if [ ! -d "$KERNEL_SRC" ]; then
    echo "[2/6] Cloning kernel source (violin-v-oss)..."
    git clone --depth 1 --filter=blob:limit=500k \
        --branch violin-v-oss \
        https://github.com/MiCode/Xiaomi_Kernel_OpenSource.git \
        "$KERNEL_SRC" 2>&1 | tail -5
else
    echo "[2/6] Kernel source already exists"
fi

# Step 3: Install Android NDK (for cross-compilation)
if [ ! -d "$NDK_DIR/android-ndk-r29" ]; then
    echo "[3/6] Downloading Android NDK r29..."
    mkdir -p "$NDK_DIR"
    cd "$NDK_DIR"
    wget -q https://dl.google.com/android/repository/android-ndk-r29-linux.zip -O ndk.zip
    unzip -q ndk.zip
    rm ndk.zip
    echo "NDK installed at $NDK_DIR/android-ndk-r29"
else
    echo "[3/6] Android NDK already installed"
fi

export NDK_ROOT="$NDK_DIR/android-ndk-r29"
export PATH="$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"

# Verify compiler
echo "Verifying cross-compiler..."
aarch64-linux-gnu-gcc --version 2>/dev/null | head -1 || \
    "$NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" --version 2>/dev/null | head -1

# Step 4: Prepare kernel config
echo "[4/6] Preparing kernel config..."
cd "$KERNEL_SRC/common-gki"

# Create merged defconfig
# GKI base + Xiaomi/O1 fragment + violin fragment
DEFCONFIG_DIR="arch/arm64/configs"
XIAOMI_CONFIGS="../xring-configs"

# Merge configs: gki_defconfig + O1_gki.fragment + xiaomi fragments
cat "$DEFCONFIG_DIR/gki_defconfig" > /tmp/violin_defconfig
[ -f "$XIAOMI_CONFIGS/O1/O1_gki.fragment" ] && cat "$XIAOMI_CONFIGS/O1/O1_gki.fragment" >> /tmp/violin_defconfig
[ -f "$XIAOMI_CONFIGS/xiaomi/xiaomi_deconfig.common" ] && cat "$XIAOMI_CONFIGS/xiaomi/xiaomi_deconfig.common" >> /tmp/violin_defconfig
[ -f "$XIAOMI_CONFIGS/xiaomi/violin/xiaomi_deconfig.violin" ] && cat "$XIAOMI_CONFIGS/xiaomi/violin/xiaomi_deconfig.violin" >> /tmp/violin_defconfig

cp /tmp/violin_defconfig "$DEFCONFIG_DIR/violin_defconfig"

# Use LLVM=1 for GKI build (standard for Android kernels)
make ARCH=arm64 LLVM=1 violin_defconfig 2>&1 | tail -5

# Enable KALLSYMS_ALL (should already be in gki_defconfig)
scripts/config --enable CONFIG_KALLSYMS
scripts/config --enable CONFIG_KALLSYMS_ALL
scripts/config --enable CONFIG_KALLSYMS_BASE_RELATIVE

# Step 5: Build kernel
echo "[5/6] Building kernel (this takes 15-60 minutes)..."
echo "Using $(nproc) cores..."

make ARCH=arm64 LLVM=1 -j$(nproc) Image 2>&1 | tail -20

# Step 6: Extract System.map
echo "[6/6] Extracting System.map..."
if [ -f "$BUILD_DIR/System.map" ]; then
    cp "$BUILD_DIR/System.map" "$WORK_DIR/outputs/System.map"
    echo "System.map copied to $WORK_DIR/outputs/System.map"
elif [ -f "System.map" ]; then
    cp System.map "$WORK_DIR/outputs/System.map"
    echo "System.map copied to $WORK_DIR/outputs/System.map"
else
    echo "WARNING: System.map not found. Looking for vmlinux..."
    find "$BUILD_DIR" -name "System.map" -o -name "vmlinux" 2>/dev/null | head -5
fi

# Also copy vmlinux if available (contains full symbols)
VMLINUX=$(find "$BUILD_DIR" -name "vmlinux" -type f 2>/dev/null | head -1)
if [ -n "$VMLINUX" ]; then
    cp "$VMLINUX" "$WORK_DIR/outputs/vmlinux"
    echo "vmlinux copied to $WORK_DIR/outputs/vmlinux"
    # Extract symbols from vmlinux
    nm "$VMLINUX" 2>/dev/null | grep -E "T |D |B " > "$WORK_DIR/outputs/vmlinux_symbols.txt"
    echo "Symbols extracted to vmlinux_symbols.txt"
fi

echo ""
echo "=========================================="
echo "BUILD COMPLETE"
echo "=========================================="
echo "Run gen_offsets.py with the System.map:"
echo "  cd $WORK_DIR"
echo "  python3 gen_offsets.py outputs/System.map"
