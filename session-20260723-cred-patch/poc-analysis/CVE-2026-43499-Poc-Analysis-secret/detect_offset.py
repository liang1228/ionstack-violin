#!/usr/bin/env python3
"""Detect the two physical-address fields required by generate_target.py."""

from __future__ import annotations

import re
import subprocess
import sys
from dataclasses import dataclass


# arm64 chooses memstart_addr by rounding the first DRAM address down to 1 GiB.
ARM64_MEMSTART_ALIGN = 1 << 30

# In an arm64 Image, the /proc/iomem "Kernel code" range starts at _stext.
# The Image load address (_text) precedes _stext by 64 KiB.
ARM64_STEXT_OFFSET = 0x10000
PAGE_SIZE = 0x1000

IOMEM_LINE = re.compile(
    r"^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.*?)\s*$"
)


@dataclass(frozen=True)
class MemoryRange:
    start: int
    end: int  # Exclusive.
    name: str

    def contains(self, other: "MemoryRange") -> bool:
        return self.start <= other.start and other.end <= self.end


def run(*args: str) -> str:
    proc = subprocess.run(
        args,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "command failed"
        raise RuntimeError(detail)
    return proc.stdout.replace("\r", "")


def list_devices() -> list[str]:
    devices: list[str] = []
    for line in run("adb", "devices").splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 2 and fields[1] == "device":
            devices.append(fields[0])
    return devices


def select_device() -> str:
    devices = list_devices()
    if not devices:
        raise RuntimeError("No authorized ADB device found.")
    if len(devices) > 1:
        print(f"warning: using first ADB device: {devices[0]}", file=sys.stderr)
    return devices[0]


def root_shell(serial: str, command: str) -> str:
    return run("adb", "-s", serial, "shell", "su", "-c", command)


def read_root_iomem(serial: str) -> str:
    identity = root_shell(serial, "id")
    if re.search(r"(?:^|\s)uid=0(?:\(|\s|$)", identity) is None:
        raise RuntimeError(f"su did not return uid 0: {identity.strip()}")

    iomem = root_shell(serial, "cat /proc/iomem")
    if not iomem.strip():
        raise RuntimeError("Root read of /proc/iomem returned no data.")
    return iomem


def parse_iomem(text: str) -> list[MemoryRange]:
    ranges: list[MemoryRange] = []
    for line in text.splitlines():
        match = IOMEM_LINE.fullmatch(line)
        if match is None:
            continue
        start = int(match.group(1), 16)
        inclusive_end = int(match.group(2), 16)
        if inclusive_end < start:
            raise RuntimeError(f"Invalid /proc/iomem range: {line.strip()}")
        ranges.append(MemoryRange(start, inclusive_end + 1, match.group(3)))
    if not ranges:
        raise RuntimeError("Failed to parse /proc/iomem.")
    return ranges


def align_down(value: int, alignment: int) -> int:
    return value & -alignment


def detect_offsets(iomem: str) -> tuple[int, int]:
    ranges = parse_iomem(iomem)
    system_ram = [item for item in ranges if item.name == "System RAM"]
    kernel_code = [item for item in ranges if item.name == "Kernel code"]

    if not system_ram:
        raise RuntimeError("System RAM is missing from /proc/iomem.")
    if len(kernel_code) != 1:
        raise RuntimeError(
            f"Expected one Kernel code range, found {len(kernel_code)}."
        )

    first_ram = min(item.start for item in system_ram)
    phys_offset = align_down(first_ram, ARM64_MEMSTART_ALIGN)
    code = kernel_code[0]
    if code.start < ARM64_STEXT_OFFSET:
        raise RuntimeError("Kernel addresses are hidden or invalid in /proc/iomem.")
    kernel_phys_load = code.start - ARM64_STEXT_OFFSET

    containing_ram = [item for item in system_ram if item.contains(code)]
    if len(containing_ram) != 1:
        raise RuntimeError("Kernel code is not contained in exactly one System RAM range.")
    ram = containing_ram[0]

    # Close the derivation loop instead of merely printing two guessed values.
    if first_ram - phys_offset >= ARM64_MEMSTART_ALIGN:
        raise RuntimeError("PHYS_OFFSET rounding invariant failed.")
    if phys_offset % ARM64_MEMSTART_ALIGN != 0:
        raise RuntimeError("PHYS_OFFSET is not 1 GiB aligned.")
    if kernel_phys_load % PAGE_SIZE != 0:
        raise RuntimeError("Kernel Image load address is not page aligned.")
    if not (ram.start <= kernel_phys_load < ram.end):
        raise RuntimeError("Kernel Image load address falls outside System RAM.")
    if kernel_phys_load + ARM64_STEXT_OFFSET != code.start:
        raise RuntimeError("Kernel code reverse-check failed.")
    if kernel_phys_load < phys_offset:
        raise RuntimeError("Kernel Image load address precedes PHYS_OFFSET.")

    return phys_offset, kernel_phys_load


def main() -> int:
    try:
        serial = select_device()
        phys_offset, kernel_phys_load = detect_offsets(read_root_iomem(serial))
        print(f"p0_phys_offset: {phys_offset:#x}")
        print(f"p0_kernel_phys_load: {kernel_phys_load:#x}")
        return 0
    except (OSError, RuntimeError) as exc:
        print(f"Failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
