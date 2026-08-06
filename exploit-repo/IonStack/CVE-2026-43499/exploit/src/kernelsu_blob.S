.section .rodata
.balign 16

/* KernelSU ksud binary — 从 KernelSU releases 下载 arm64 版本
 * 放置路径: build/embed/ksud_aarch64
 * GitHub: https://github.com/tiann/KernelSU/releases */
.global embedded_ksud_start
.type embedded_ksud_start, %object
embedded_ksud_start:
.incbin "build/embed/ksud_aarch64"

.global embedded_ksud_end
.type embedded_ksud_end, %object
embedded_ksud_end:
.byte 0

/* KernelSU kernelsu.ko — 可选，LKM 模式需要
 * 放置路径: build/embed/kernelsu_aarch64.ko */
.global embedded_kernelsu_ko_start
.type embedded_kernelsu_ko_start, %object
embedded_kernelsu_ko_start:
.incbin "build/embed/kernelsu_aarch64.ko"

.global embedded_kernelsu_ko_end
.type embedded_kernelsu_ko_end, %object
embedded_kernelsu_ko_end:
.byte 0
