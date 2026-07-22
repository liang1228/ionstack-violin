/*
 * xbl_config DTB 解析 — 从 XBL config 分区提取 p0_phys_offset 和 p0_kernel_phys_load
 *
 * Qualcomm 启动链中，内存布局编码在 XBL config 分区的 DTB 里。
 * 扫描 FDT magic (0xD00DFEED)，遍历所有 DTB，解析 FDT token，
 * 找带 mem-label 属性的内存节点，提取 base/size/label。
 *
 * p0_phys_offset = NOMAP.base 向下对齐到 1GB
 * p0_kernel_phys_load = Kernel.base
 *
 * 不需要 root！XBL config 分区通常可由 shell 用户读取。
 */

#include "common.h"
#include <stdint.h>
#include <string.h>

#define FDT_MAGIC 0xD00DFEED
#define FDT_BEGIN_NODE 1
#define FDT_END_NODE   2
#define FDT_PROP       3
#define FDT_NOP        4
#define FDT_END        9

#define ARM64_MEMSTART_ALIGN (1ULL << 30)  /* 1 GB */
#define PAGE_SIZE_4K 0x1000

struct xbl_mem_region {
  uint64_t base;
  uint64_t size;
  char label[32];
};

struct xbl_profile {
  uint64_t p0_phys_offset;
  uint64_t p0_kernel_phys_load;
  uint64_t kernel_region_size;
  int found;
};

/* ---- FDT header (big-endian) ---- */
struct fdt_header {
  uint32_t magic;
  uint32_t totalsize;
  uint32_t off_dt_struct;
  uint32_t off_dt_strings;
  uint32_t off_mem_rsvmap;
  uint32_t version;
  uint32_t last_comp_version;
  uint32_t boot_cpuid_phys;
  uint32_t size_dt_strings;
  uint32_t size_dt_struct;
};

static uint32_t be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8)  | (uint32_t)p[3];
}

static uint64_t be_reg(const uint8_t *p, int cells) {
  if (cells == 2) {
    return ((uint64_t)be32(p) << 32) | be32(p + 4);
  }
  return be32(p);
}

/* 查找 DTB strings block 中的属性名 */
static const char *fdt_string(const uint8_t *strings, uint32_t strings_size,
                              uint32_t off) {
  if (off >= strings_size) return NULL;
  return (const char *)(strings + off);
}

/* 解析单个 DTB，提取 NOMAP 和 Kernel 内存区域 */
static int parse_fdt_regions(const uint8_t *data, size_t len,
                             struct xbl_mem_region *regions, int max_regions) {
  if (len < sizeof(struct fdt_header)) return 0;

  struct fdt_header hdr;
  memcpy(&hdr, data, sizeof(hdr));
  hdr.magic         = be32(data + 0);
  hdr.totalsize     = be32(data + 4);
  hdr.off_dt_struct = be32(data + 8);
  hdr.off_dt_strings = be32(data + 12);
  hdr.version       = be32(data + 20);
  hdr.size_dt_strings = be32(data + 32);
  hdr.size_dt_struct  = be32(data + 36);

  if (hdr.magic != FDT_MAGIC) return 0;
  if (hdr.totalsize > len) return 0;
  if (hdr.version < 16) return 0;

  const uint8_t *str_block = data + hdr.off_dt_strings;
  uint32_t str_size = hdr.size_dt_strings;
  const uint8_t *struct_block = data + hdr.off_dt_struct;
  uint32_t struct_size = hdr.size_dt_struct;

  if (hdr.off_dt_strings + str_size > len) return 0;
  if (hdr.off_dt_struct + struct_size > len) return 0;

  int count = 0;
  uint32_t sp = 0;

  /* 节点栈 (用于跟踪 address-cells / size-cells) */
  int addr_cells_stack[16];
  int size_cells_stack[16];
  int depth = 0;
  addr_cells_stack[0] = 2;  /* 默认 #address-cells = 2 */
  size_cells_stack[0] = 1;  /* 默认 #size-cells = 1 */

  /* 当前节点状态 */
  char node_label[32] = {0};
  uint8_t node_reg[32] = {0};
  int node_reg_size = 0;
  int node_has_label = 0;
  int node_has_reg = 0;
  int cur_addr_cells = 2;
  int cur_size_cells = 1;

  while (sp + 4 <= struct_size) {
    uint32_t token = be32(struct_block + sp);
    sp += 4;

    switch (token) {
    case FDT_BEGIN_NODE: {
      /* 跳过节点名 (null-terminated) */
      while (sp < struct_size && struct_block[sp] != 0) sp++;
      if (sp < struct_size) sp++;  /* skip null */
      /* 4-byte align */
      sp = (sp + 3) & ~3U;

      depth++;
      if (depth >= 16) depth = 15;
      addr_cells_stack[depth] = cur_addr_cells;
      size_cells_stack[depth] = cur_size_cells;

      /* 重置节点状态 */
      memset(node_label, 0, sizeof(node_label));
      node_reg_size = 0;
      node_has_label = 0;
      node_has_reg = 0;
      break;
    }

    case FDT_END_NODE: {
      /* 检查是否有 mem-label=NOMAP 或 Kernel */
      if (node_has_label && node_has_reg && count < max_regions) {
        if (strcmp(node_label, "NOMAP") == 0 ||
            strcmp(node_label, "Kernel") == 0) {
          int parent_addr = depth > 0 ? addr_cells_stack[depth] : 2;
          int parent_size = depth > 0 ? size_cells_stack[depth] : 1;
          int entry_size = parent_addr * 4 + parent_size * 4;
          if (node_reg_size >= entry_size) {
            uint64_t base = be_reg(node_reg, parent_addr);
            uint64_t size = be_reg(node_reg + parent_addr * 4, parent_size);
            if (base > 0 && size > 0) {
              regions[count].base = base;
              regions[count].size = size;
              strncpy(regions[count].label, node_label,
                      sizeof(regions[count].label) - 1);
              count++;
            }
          }
        }
      }

      if (depth > 0) depth--;
      cur_addr_cells = addr_cells_stack[depth];
      cur_size_cells = size_cells_stack[depth];
      break;
    }

    case FDT_PROP: {
      if (sp + 8 > struct_size) goto done;
      uint32_t val_size = be32(struct_block + sp);
      uint32_t name_off = be32(struct_block + sp + 4);
      sp += 8;

      const char *name = fdt_string(str_block, str_size, name_off);
      const uint8_t *val = struct_block + sp;

      if (name) {
        if (strcmp(name, "#address-cells") == 0 && val_size >= 4) {
          cur_addr_cells = (int)be32(val);
        } else if (strcmp(name, "#size-cells") == 0 && val_size >= 4) {
          cur_size_cells = (int)be32(val);
        } else if (strcmp(name, "reg") == 0) {
          if (val_size <= sizeof(node_reg)) {
            memcpy(node_reg, val, val_size);
            node_reg_size = (int)val_size;
            node_has_reg = 1;
          }
        } else if (strcmp(name, "mem-label") == 0) {
          /* 属性值是 null-terminated ASCII 字符串 */
          uint32_t slen = val_size;
          /* 找 null terminator */
          for (uint32_t i = 0; i < val_size; i++) {
            if (val[i] == 0) { slen = i; break; }
          }
          if (slen >= sizeof(node_label)) slen = sizeof(node_label) - 1;
          memcpy(node_label, val, slen);
          node_label[slen] = 0;
          node_has_label = 1;
        }
      }

      /* 跳过属性值，4-byte align */
      sp += val_size;
      sp = (sp + 3) & ~3U;
      break;
    }

    case FDT_NOP:
      break;

    case FDT_END:
      goto done;

    default:
      goto done;
    }
  }

done:
  return count;
}

/*
 * xbl_config_find_profile: 扫描 xbl_config 分区，提取 p0_phys_offset 和 p0_kernel_phys_load
 *
 * 分区路径 (按优先级):
 *   /dev/block/bootdevice/by-name/xbl_config
 *   /dev/block/by-name/xbl_config
 *   /dev/block/sda (需手动指定偏移)
 *
 * 返回: 0=成功, -1=失败
 */
int xbl_config_find_profile(struct xbl_profile *out) {
  static const char *paths[] = {
    "/dev/block/bootdevice/by-name/xbl_config",
    "/dev/block/by-name/xbl_config",
    "/dev/block/mmcblk0p3",  /* 常见 xbl_config 分区号 */
    NULL,
  };

  memset(out, 0, sizeof(*out));

  uint8_t *data = NULL;
  size_t data_size = 0;

  for (int i = 0; paths[i]; i++) {
    int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
    if (fd < 0) continue;

    /* 读取分区 (通常 1-4MB) */
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); continue; }
    data_size = (size_t)st.st_size;
    if (data_size == 0 || data_size > 16 * 1024 * 1024) {
      /* 尝试固定大小读取 */
      data_size = 4 * 1024 * 1024;
    }

    data = malloc(data_size);
    if (!data) { close(fd); continue; }

    ssize_t n = read(fd, data, data_size);
    close(fd);
    if (n <= (ssize_t)sizeof(struct fdt_header)) {
      free(data);
      data = NULL;
      continue;
    }
    data_size = (size_t)n;
    pr_info("xbl_config: read %zu bytes from %s\n", data_size, paths[i]);
    break;
  }

  if (!data) {
    pr_warning("xbl_config: no readable partition found\n");
    return -1;
  }

  /* 扫描所有 FDT magic */
  struct xbl_mem_region regions[64];
  int total_regions = 0;

  const uint8_t *p = data;
  size_t remaining = data_size;
  while (remaining >= 8) {
    const uint8_t *found = memchr(p, 0xD0, remaining - 3);
    if (!found) break;

    size_t pos = (size_t)(found - data);
    if (be32(data + pos) != FDT_MAGIC) {
      size_t skip = pos + 4;
      remaining = data_size - skip;
      p = data + skip;
      continue;
    }

    uint32_t fdt_size = be32(data + pos + 4);
    if (fdt_size < 40 || pos + fdt_size > data_size) {
      size_t skip = pos + 4;
      remaining = data_size - skip;
      p = data + skip;
      continue;
    }

    struct xbl_mem_region dtb_regions[16];
    int n = parse_fdt_regions(data + pos, fdt_size, dtb_regions, 16);
    if (n > 0 && total_regions + n <= 64) {
      for (int j = 0; j < n; j++) {
        regions[total_regions++] = dtb_regions[j];
      }
      pr_info("xbl_config: DTB at +0x%zx parsed %d memory regions\n", pos, n);
    }

    size_t skip = pos + fdt_size;
    remaining = data_size - skip;
    p = data + skip;
  }

  free(data);

  if (total_regions == 0) {
    pr_warning("xbl_config: no memory regions found in any DTB\n");
    return -1;
  }

  /* 查找 NOMAP 和 Kernel 区域 */
  uint64_t nomap_base = 0, nomap_size = 0;
  uint64_t kernel_base = 0, kernel_size = 0;

  for (int i = 0; i < total_regions; i++) {
    pr_info("xbl_config: region[%d] base=0x%llx size=0x%llx label=%s\n",
            i, (unsigned long long)regions[i].base,
            (unsigned long long)regions[i].size, regions[i].label);
    if (strcmp(regions[i].label, "NOMAP") == 0) {
      nomap_base = regions[i].base;
      nomap_size = regions[i].size;
    } else if (strcmp(regions[i].label, "Kernel") == 0) {
      kernel_base = regions[i].base;
      kernel_size = regions[i].size;
    }
  }

  if (nomap_base == 0 || kernel_base == 0) {
    pr_warning("xbl_config: NOMAP or Kernel region not found\n");
    return -1;
  }

  /* p0_phys_offset = NOMAP.base 向下对齐到 1GB */
  out->p0_phys_offset = nomap_base & ~(ARM64_MEMSTART_ALIGN - 1);
  out->p0_kernel_phys_load = kernel_base;
  out->kernel_region_size = kernel_size;
  out->found = 1;

  pr_success("xbl_config: p0_phys_offset=0x%llx p0_kernel_phys_load=0x%llx "
             "kernel_size=0x%llx\n",
             (unsigned long long)out->p0_phys_offset,
             (unsigned long long)out->p0_kernel_phys_load,
             (unsigned long long)out->kernel_region_size);

  return 0;
}
