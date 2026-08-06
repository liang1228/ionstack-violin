import importlib.util
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).parents[1] / "audit_violin_kernel_baseline.py"
SPEC = importlib.util.spec_from_file_location("audit_violin_kernel_baseline", SCRIPT)
audit = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(audit)


class AuditViolinKernelBaselineTests(unittest.TestCase):
    def test_happy_path_verifies_offsets_and_physical_layout(self):
        target = """
#define P0_PHYS_OFFSET 0x0ULL
#define P0_KERNEL_PHYS_LOAD 0x00210000ULL
#define FOO_OFF 0x1000ULL  /* symbol: foo */
"""
        kallsyms = """
ffffffe387200000 T _text
ffffffe387201000 T foo
ffffffe388000000 T foo [module_copy]
"""
        iomem = """
00200000-02ffffff : System RAM
  00210000-01eaffff : Kernel code
"""
        result = audit.audit_texts(target, kallsyms, iomem)
        self.assertTrue(result["ok"])
        self.assertEqual(result["summary"]["checked_symbol_offsets"], 1)
        self.assertEqual(result["summary"]["mismatches"], 0)

    def test_rejects_offset_mismatch(self):
        target = """
#define P0_PHYS_OFFSET 0x0ULL
#define P0_KERNEL_PHYS_LOAD 0x00210000ULL
#define FOO_OFF 0x2000ULL  /* symbol: foo */
"""
        kallsyms = """
ffffffe387200000 T _text
ffffffe387201000 T foo
"""
        iomem = """
00200000-02ffffff : System RAM
  00210000-01eaffff : Kernel code
"""
        result = audit.audit_texts(target, kallsyms, iomem)
        self.assertFalse(result["ok"])
        self.assertEqual(result["summary"]["mismatches"], 1)


if __name__ == "__main__":
    unittest.main()
