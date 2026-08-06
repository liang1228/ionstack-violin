# KernelSU ko 编译指南 — Xiaomi Pad 7S Pro (violin)

## 设备信息
- 内核: 6.6.77-android15-8-g5770c661275f-abogki443185593-4k
- 编译器: Android clang 18.0.0 (NDK r29)
- 架构: arm64

## 文件说明
- `kernel-6.6.77-src.tar.gz` — 内核头文件 + scripts + .config
- `kernel-6.6.77-configs.tar.gz` — xring 配置文件

## 编译步骤

```bash
# 1. 解压内核源码
mkdir -p ~/kernel-build && cd ~/kernel-build
tar xzf kernel-6.6.77-src.tar.gz
tar xzf kernel-6.6.77-configs.tar.gz

# 2. 安装 NDK (如果没装)
# 下载 android-ndk-r29 到 ~/android-ndk-cache/android-ndk-r29

# 3. 生成 Module.symvers
export ARCH=arm64
export CC=clang
export LLVM=1
# 用 NDK clang
export PATH=~/android-ndk-cache/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

# 注: .config 已包含在 tar.gz 中
# 如果需要重新生成 defconfig:
# make violin_defconfig

make modules_prepare -j$(nproc)
make modules -j$(nproc)

# 4. 克隆 KernelSU 源码
git clone https://github.com/tiann/KernelSU.git
cd KernelSU/kernel

# 5. 编译 ko
make -C ~/kernel-build KERNEL_SRC=~/kernel-build MODULE.symvers=~/kernel-build/Module.symvers

# 6. 输出: kernelsu.ko
```

## 关键偏移量 (violin target)
```
KIMAGE_TEXT_BASE     = 0xffffffc008000000
INIT_CRED_OFF        = 0x020f0548
SELINUX_ENFORCING_OFF= 0x0207cae0
TASK_CRED_OFF        = 0x820
TASK_REAL_CRED_OFF   = 0x818
```

## 注意
- kCFI 已启用 (`CONFIG_CFI_CLANG=y`, `CONFIG_CFI_PERMISSIVE is not set`)
- CONFIG_MODVERSIONS=y (需要 Module.symvers)
- 设备内核版本: 6.6.77-android15-8
