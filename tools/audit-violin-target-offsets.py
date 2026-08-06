"""Read-only audit of Violin target image-relative symbols against rooted same-build kallsyms."""
from pathlib import Path
import re
ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / 'exploit-repo/IonStack/CVE-2026-43499/exploit/src/targets/violin-v-oss/target.h'
KALLSYMS = ROOT / 'analysis_outputs/violin-kernel-info2/violin-kernel-info/kallsyms.txt'
OUT = ROOT / 'analysis_outputs/violin-target-offset-audit-20260714.txt'
header = HEADER.read_text(encoding='utf-8')
syms = {}
for line in KALLSYMS.read_text(encoding='utf-8', errors='replace').splitlines():
    m = re.match(r'([0-9a-fA-F]+)\s+\S\s+(.+)$', line)
    if m: syms[m.group(2).strip()] = int(m.group(1), 16)
text = syms['_text']
checks = [('ASHMEM_MISC_FOPS_OFF','misc_fops'),('ASHMEM_FOPS_OFF','ashmem_fops'),('ASHMEM_IOCTL_OFF','ashmem_ioctl'),('ASHMEM_COMPAT_IOCTL_OFF','compat_ashmem_ioctl'),('ASHMEM_MMAP_OFF','ashmem_mmap'),('ASHMEM_OPEN_OFF','ashmem_open'),('ASHMEM_RELEASE_OFF','ashmem_release'),('ASHMEM_SHOW_FDINFO_OFF','ashmem_show_fdinfo'),('CONFIGFS_READ_ITER_OFF','configfs_read_iter'),('CONFIGFS_BIN_WRITE_ITER_OFF','configfs_bin_write_iter'),('COPY_SPLICE_READ_OFF','copy_splice_read'),('NOOP_LLSEEK_OFF','noop_llseek'),('INIT_TASK_OFF','init_task'),('INIT_CRED_OFF','init_cred'),('INIT_UTS_NS_OFF','init_uts_ns'),('EMPTY_ZERO_PAGE_OFF','empty_zero_page'),('ROOT_TASK_GROUP_OFF','root_task_group'),('SELINUX_BLOB_SIZES_OFF','selinux_blob_sizes'),('SELINUX_ENFORCING_OFF','selinux_enforcing_boot'),('SECURITY_HOOK_HEADS_OFF','security_hook_heads'),('KMALLOC_CACHES_OFF','kmalloc_caches'),('ANON_PIPE_BUF_OPS_OFF','anon_pipe_buf_ops'),('SLIDE_NFULNL_LOGGER_OFF','nfulnl_logger'),('SLIDE_LOGGERS_0_1_OFF','loggers'),('SLIDE_RANDOM_BOOT_ID_DATA_OFF','sysctl_bootid'),('SLIDE_SYSCTL_BOOTID_OFF','sysctl_bootid')]
def macro(name):
    m = re.search(rf'^#define\s+{name}\s+(0x[0-9a-fA-F]+)ULL', header, re.M)
    if not m: raise RuntimeError(f'cannot parse literal macro: {name}')
    return int(m.group(1), 16)
rows=[]
for name, symbol in checks:
    wanted, actual = macro(name), syms[symbol]-text
    rows.append((name,symbol,wanted,actual,wanted==actual))
with OUT.open('w',encoding='utf-8',newline='\n') as fp:
    fp.write(f'KALLSYMS={KALLSYMS}\nTEXT=0x{text:016x}\n')
    for name,symbol,wanted,actual,ok in rows: fp.write(f'{"OK" if ok else "FAIL":4} {name:34} sym={symbol:28} header=0x{wanted:08x} actual=0x{actual:08x} delta={wanted-actual:+#x}\n')
    fp.write(f'SUMMARY {sum(row[-1] for row in rows)}/{len(rows)} image-relative symbol offsets exact\n')
if not all(row[-1] for row in rows): raise SystemExit(1)
