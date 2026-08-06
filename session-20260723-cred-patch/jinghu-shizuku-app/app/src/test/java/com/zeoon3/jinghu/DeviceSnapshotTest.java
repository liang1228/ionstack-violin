package com.zeoon3.jinghu;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public final class DeviceSnapshotTest {
    private static final String VALID_PREFLIGHT = String.join("\n",
            "BOOT_ID=boot-123",
            "DEVICE=jinghu",
            "MODEL=25053RP5CC",
            "KERNEL=" + JinghuRunner.EXPECTED_KERNEL,
            "ENFORCE=Enforcing",
            "BOOT_COMPLETED=1",
            "KSU_MODULE=0",
            "MARKER=0");

    @Test
    public void validPreflightCanRun() {
        DeviceSnapshot snapshot = DeviceSnapshot.from(VALID_PREFLIGHT);

        assertTrue(snapshot.canRun());
        assertEquals("boot-123", snapshot.bootId);
        assertEquals("25053RP5CC", snapshot.model);
    }

    @Test
    public void valueMayContainEqualsSign() {
        DeviceSnapshot snapshot = DeviceSnapshot.from(
                VALID_PREFLIGHT + "\nMODEL=Pad=Engineering");

        assertEquals("Pad=Engineering", snapshot.model);
    }

    @Test
    public void markerRejectsSecondRunInSameBoot() {
        DeviceSnapshot snapshot = DeviceSnapshot.from(
                VALID_PREFLIGHT.replace("MARKER=0", "MARKER=1"));

        assertFalse(snapshot.canRun());
    }

    @Test
    public void kernelMismatchIsRejected() {
        DeviceSnapshot snapshot = DeviceSnapshot.from(
                VALID_PREFLIGHT.replace(JinghuRunner.EXPECTED_KERNEL, "6.6.77-other"));

        assertFalse(snapshot.canRun());
    }

    @Test
    public void missingFieldsUseSafeDefaults() {
        DeviceSnapshot snapshot = DeviceSnapshot.from("BOOT_ID=boot-only");

        assertFalse(snapshot.canRun());
        assertEquals("unknown", snapshot.device);
        assertEquals("0", snapshot.ksuModule);
    }
}
