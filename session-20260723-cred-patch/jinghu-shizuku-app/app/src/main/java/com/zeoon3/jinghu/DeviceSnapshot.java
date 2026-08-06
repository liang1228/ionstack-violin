package com.zeoon3.jinghu;

import java.util.HashMap;
import java.util.Map;

/** Immutable result of the device-side preflight gate. */
public final class DeviceSnapshot {
    public final String bootId;
    public final String device;
    public final String model;
    public final String kernel;
    public final String enforce;
    public final String bootCompleted;
    public final String ksuModule;
    public final String marker;

    private DeviceSnapshot(Map<String, String> values) {
        bootId = values.getOrDefault("BOOT_ID", "");
        device = values.getOrDefault("DEVICE", "unknown");
        model = values.getOrDefault("MODEL", "unknown");
        kernel = values.getOrDefault("KERNEL", "unknown");
        enforce = values.getOrDefault("ENFORCE", "unknown");
        bootCompleted = values.getOrDefault("BOOT_COMPLETED", "");
        ksuModule = values.getOrDefault("KSU_MODULE", "0");
        marker = values.getOrDefault("MARKER", "0");
    }

    public static DeviceSnapshot from(String text) {
        Map<String, String> values = new HashMap<>();
        for (String line : text.split("\\R")) {
            int separator = line.indexOf('=');
            if (separator > 0) {
                values.put(line.substring(0, separator), line.substring(separator + 1).trim());
            }
        }
        return new DeviceSnapshot(values);
    }

    public boolean canRun() {
        return JinghuRunner.EXPECTED_KERNEL.equals(kernel)
                && "Enforcing".equalsIgnoreCase(enforce)
                && "1".equals(bootCompleted)
                && !"1".equals(marker)
                && "0".equals(ksuModule);
    }
}
