package com.zeoon3.jinghu;

import android.content.Context;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

/** Persistent journal for payload runs, including process death and reboot recovery. */
public final class RunLogStore {
    private static final String ACTIVE_FILE_NAME = "active-run.properties";
    private static final String LOG_DIR_NAME = "run-logs";

    private final File logDir;
    private final File activeFile;
    private final File eventsFile;

    public RunLogStore(Context context) {
        File root = context.getApplicationContext().getFilesDir();
        logDir = new File(root, LOG_DIR_NAME);
        activeFile = new File(root, ACTIVE_FILE_NAME);
        eventsFile = new File(logDir, "app-events.log");
        //noinspection ResultOfMethodCallIgnored
        logDir.mkdirs();
    }

    public synchronized String beginRun(String payloadName, String payloadSha, String bootId) {
        String id = new SimpleDateFormat("yyyyMMdd-HHmmss-SSS", Locale.ROOT)
                .format(new Date());
        File logFile = new File(logDir, id + ".log");
        Properties properties = new Properties();
        properties.setProperty("id", id);
        properties.setProperty("status", "RUNNING");
        properties.setProperty("started_at", Long.toString(System.currentTimeMillis()));
        properties.setProperty("boot_id", safe(bootId));
        properties.setProperty("payload_name", safe(payloadName));
        properties.setProperty("payload_sha256", safe(payloadSha));
        properties.setProperty("log_file", logFile.getAbsolutePath());
        try {
            writeProperties(properties);
            appendTo(logFile, "# Jinghu v20 run journal\n");
            appendTo(logFile, "RUN_ID=" + id + "\n");
            appendTo(logFile, "RUN_STARTED_AT=" + new Date() + "\n");
            appendTo(logFile, "BOOT_ID=" + safe(bootId) + "\n");
            appendTo(logFile, "PAYLOAD_NAME=" + safe(payloadName) + "\n");
            appendTo(logFile, "PAYLOAD_SHA256=" + safe(payloadSha) + "\n");
        } catch (IOException ignored) {
            // The execution path must remain usable even if local storage is unavailable.
        }
        return id;
    }

    public synchronized void append(String runId, String line) {
        Properties properties = readProperties();
        if (properties == null || !runId.equals(properties.getProperty("id"))) {
            return;
        }
        File logFile = new File(properties.getProperty("log_file", ""));
        try {
            appendTo(logFile, line + "\n");
        } catch (IOException ignored) {
            // Never interrupt the payload because journal storage failed.
        }
    }

    public synchronized void finish(String runId, boolean success, String reason) {
        Properties properties = readProperties();
        if (properties == null || !runId.equals(properties.getProperty("id"))) {
            return;
        }
        File logFile = new File(properties.getProperty("log_file", ""));
        String status = success ? "SUCCESS" : "FAILED";
        try {
            appendTo(logFile, "RUN_STATUS=" + status + "\n");
            if (reason != null && !reason.isEmpty()) {
                appendTo(logFile, "RUN_REASON=" + reason + "\n");
            }
            properties.setProperty("status", status);
            properties.setProperty("finished_at", Long.toString(System.currentTimeMillis()));
            writeProperties(properties);
            // A completed run is represented by its immutable log; the journal is only for
            // detecting an interrupted run after process death or reboot.
            //noinspection ResultOfMethodCallIgnored
            activeFile.delete();
        } catch (IOException ignored) {
            // Keep the journal if finalization could not be persisted.
        }
    }

    public synchronized String recoverOnLaunch() {
        return recover("PROCESS_RESTART_RECOVERY=1", "previous run was interrupted before completion");
    }

    public synchronized String recoverAfterBoot() {
        return recover("BOOT_RECEIVER_RECOVERY=1", "previous run was interrupted by a device reboot");
    }

    /** Persists app errors and setup events even when no payload run is active. */
    public synchronized void appendEvent(String line) {
        String value = line == null ? "" : line.replace('\n', ' ').replace('\r', ' ');
        try {
            appendTo(eventsFile, new Date() + " " + value + "\n");
        } catch (IOException ignored) {
            // Logging must never break the UI or execution path.
        }
    }

    public synchronized List<File> listLogs() {
        File[] files = logDir.listFiles((dir, name) -> name.endsWith(".log"));
        if (files == null) {
            return new ArrayList<>();
        }
        Arrays.sort(files, Comparator.comparingLong(File::lastModified).reversed());
        return new ArrayList<>(Arrays.asList(files));
    }

    public synchronized String readLatestLogs(int maxChars) {
        StringBuilder result = new StringBuilder();
        List<File> files = listLogs();
        for (File file : files) {
            if (result.length() > 0) {
                result.append("\n\n");
            }
            result.append("===== ").append(file.getName()).append(" =====\n");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new FileInputStream(file), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null && result.length() < maxChars) {
                    result.append(line).append('\n');
                }
            } catch (IOException e) {
                result.append("LOG_READ_ERROR=").append(e.getMessage()).append('\n');
            }
            if (result.length() >= maxChars) {
                break;
            }
        }
        return result.length() == 0 ? "暂无已保存运行日志" : result.toString();
    }

    private String recover(String marker, String reason) {
        Properties properties = readProperties();
        if (properties == null || !"RUNNING".equals(properties.getProperty("status"))) {
            return null;
        }
        File logFile = new File(properties.getProperty("log_file", ""));
        try {
            appendTo(logFile, marker + "\n");
            appendTo(logFile, "APP_ERROR=" + reason + "\n");
            appendTo(logFile, "RUN_STATUS=INTERRUPTED\n");
            properties.setProperty("status", "INTERRUPTED");
            properties.setProperty("recovered_at", Long.toString(System.currentTimeMillis()));
            writeProperties(properties);
            //noinspection ResultOfMethodCallIgnored
            activeFile.delete();
            return reason;
        } catch (IOException ignored) {
            return "run journal recovery failed to persist";
        }
    }

    private Properties readProperties() {
        if (!activeFile.isFile()) {
            return null;
        }
        Properties properties = new Properties();
        try (FileInputStream input = new FileInputStream(activeFile)) {
            properties.load(input);
            return properties;
        } catch (IOException ignored) {
            return null;
        }
    }

    private void writeProperties(Properties properties) throws IOException {
        File temp = new File(activeFile.getParentFile(), ACTIVE_FILE_NAME + ".tmp");
        try (OutputStreamWriter writer = new OutputStreamWriter(
                new FileOutputStream(temp), StandardCharsets.UTF_8)) {
            properties.store(writer, "Jinghu run journal");
        }
        if (!temp.renameTo(activeFile)) {
            throw new IOException("cannot replace active run journal");
        }
    }

    private static void appendTo(File file, String content) throws IOException {
        File parent = file.getParentFile();
        if (parent != null) {
            parent.mkdirs();
        }
        try (OutputStreamWriter writer = new OutputStreamWriter(
                new FileOutputStream(file, true), StandardCharsets.UTF_8)) {
            writer.write(content);
        }
    }

    private static String safe(String value) {
        return value == null ? "" : value.replace('\n', ' ').replace('\r', ' ');
    }
}
