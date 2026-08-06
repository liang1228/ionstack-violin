package com.zeoon3.jinghu;

import android.app.Application;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import rikka.shizuku.Shizuku;

/** Owns app state and long-running work independently from the Activity lifecycle. */
public final class JinghuViewModel extends AndroidViewModel {
    public enum ShizukuState {
        INACTIVE,
        UNAUTHORIZED,
        AUTHORIZED
    }

    public static final class UiState {
        public final ShizukuState shizukuState;
        public final DeviceSnapshot snapshot;
        public final boolean busy;
        public final String output;
        public final String payloadName;
        public final String payloadSha256;
        public final boolean defaultPayload;

        private UiState(ShizukuState shizukuState, DeviceSnapshot snapshot,
                        boolean busy, String output, String payloadName,
                        String payloadSha256, boolean defaultPayload) {
            this.shizukuState = shizukuState;
            this.snapshot = snapshot;
            this.busy = busy;
            this.output = output;
            this.payloadName = payloadName;
            this.payloadSha256 = payloadSha256;
            this.defaultPayload = defaultPayload;
        }

        public boolean canRun() {
            return !busy && shizukuState == ShizukuState.AUTHORIZED
                    && snapshot != null && snapshot.canRun();
        }
    }

    /** One-shot lifecycle-safe event wrapper for dialogs. */
    public static final class Event<T> {
        private final T value;
        private boolean handled;

        private Event(T value) {
            this.value = value;
        }

        public synchronized T consume() {
            if (handled) {
                return null;
            }
            handled = true;
            return value;
        }
    }

    private final Object stateLock = new Object();
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final JinghuRunner runner;
    private final RunLogStore logStore;
    private final MutableLiveData<UiState> uiState = new MutableLiveData<>();
    private final MutableLiveData<Event<String>> savedLogsEvent = new MutableLiveData<>();

    private ShizukuState shizukuState = ShizukuState.INACTIVE;
    private DeviceSnapshot snapshot;
    private boolean busy;
    private String output;
    private String payloadName;
    private String payloadSha256;
    private boolean defaultPayload;
    private volatile String activeRunId;

    public JinghuViewModel(@NonNull Application application) {
        super(application);
        runner = new JinghuRunner(application);
        logStore = new RunLogStore(application);
        output = application.getString(R.string.output_waiting);
        synchronized (stateLock) {
            refreshPayloadLocked();
            uiState.setValue(buildStateLocked());
        }
        String recovery = logStore.recoverOnLaunch();
        if (recovery != null) {
            appendLine("RECOVERY=上一次运行未正常结束：" + recovery);
        }
    }

    public LiveData<UiState> uiState() {
        return uiState;
    }

    public LiveData<Event<String>> savedLogsEvent() {
        return savedLogsEvent;
    }

    public UiState currentState() {
        UiState value = uiState.getValue();
        if (value != null) {
            return value;
        }
        synchronized (stateLock) {
            return buildStateLocked();
        }
    }

    public void refreshShizukuState() {
        ShizukuState next;
        try {
            if (!Shizuku.pingBinder()) {
                next = ShizukuState.INACTIVE;
            } else if (Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED) {
                next = ShizukuState.AUTHORIZED;
            } else {
                next = ShizukuState.UNAUTHORIZED;
            }
        } catch (RuntimeException e) {
            next = ShizukuState.INACTIVE;
        }

        boolean shouldLoadPreflight;
        synchronized (stateLock) {
            shizukuState = next;
            shouldLoadPreflight = next == ShizukuState.AUTHORIZED
                    && snapshot == null && !busy;
            publishLocked();
        }
        if (shouldLoadPreflight) {
            loadPreflight();
        }
    }

    public void loadPreflight() {
        if (!beginBusyOperation(true)) {
            return;
        }
        appendLine("--- 读取设备门禁 ---");
        executor.execute(() -> {
            JinghuRunner.ShellResult result = safeRun(runner::preflight);
            appendResult(result, false);
            synchronized (stateLock) {
                snapshot = DeviceSnapshot.from(result.text());
                busy = false;
                publishLocked();
            }
        });
    }

    public void installManager() {
        if (!beginBusyOperation(true)) {
            return;
        }
        appendLine("--- 校验并安装 KernelSU Manager ---");
        executor.execute(() -> {
            JinghuRunner.ShellResult result = safeRun(() -> {
                if (!runner.verifyLocalAsset(JinghuRunner.MANAGER_ASSET,
                        JinghuRunner.EXPECTED_MANAGER_SHA256)) {
                    return error("APP_ERROR=Manager 内置哈希不匹配");
                }
                JinghuRunner.ShellResult copy = runner.copyAsset(
                        JinghuRunner.MANAGER_ASSET, JinghuRunner.MANAGER_REMOTE);
                if (copy.exitCode != 0
                        || !copy.contains(JinghuRunner.EXPECTED_MANAGER_SHA256)) {
                    return new JinghuRunner.ShellResult(
                            merge(copy.lines, "APP_ERROR=Manager 远端哈希校验失败"), -1, false);
                }
                return runner.installManager(null);
            });
            appendResult(result, false);
            appendLine(result.exitCode == 0
                    ? "MANAGER_INSTALL=success" : "MANAGER_INSTALL=failed");
            finishBusyOperation();
        });
    }

    public void runPayload(boolean shouldInstallManager) {
        DeviceSnapshot currentSnapshot;
        synchronized (stateLock) {
            currentSnapshot = snapshot;
            if (busy || shizukuState != ShizukuState.AUTHORIZED
                    || currentSnapshot == null || !currentSnapshot.canRun()) {
                return;
            }
            busy = true;
            publishLocked();
        }

        final String runId = logStore.beginRun(
                payloadName, payloadSha256, currentSnapshot.bootId);
        activeRunId = runId;
        appendLine("--- 开始一键流程 ---");
        appendLine("PAYLOAD_NAME=" + payloadName);
        appendLine("PAYLOAD_SHA256=" + payloadSha256);

        executor.execute(() -> {
            JinghuRunner.ShellResult result = safeRun(() -> {
                if (!runner.verifySelectedPayload()) {
                    return error("APP_ERROR=payload 本地 ELF/哈希校验失败");
                }

                JinghuRunner.ShellResult copy =
                        runner.copySelectedPayload(JinghuRunner.PAYLOAD_REMOTE);
                if (copy.exitCode != 0 || !copy.contains(payloadSha256)) {
                    return new JinghuRunner.ShellResult(
                            merge(copy.lines, "APP_ERROR=payload 远端哈希校验失败"), -1, false);
                }
                appendLines(copy.lines);

                if (shouldInstallManager) {
                    JinghuRunner.ShellResult managerResult = installManagerBeforePayload();
                    if (managerResult.exitCode != 0) {
                        return managerResult;
                    }
                }
                return runner.runPayload(this::appendLine);
            });

            boolean streamed = result.contains("RUN_BOOT_ID=")
                    || result.contains("PAYLOAD_BEGIN=1");
            appendResult(result, streamed);
            boolean success = result.exitCode == 0 && result.contains("RUN_FINISHED=1");
            appendLine(success
                    ? "流程结束：请打开 Manager 检查 KernelSU 状态。"
                    : "流程未形成完成标记；已自动保存错误日志，请不要在本 boot 重试。");
            logStore.finish(runId, success,
                    success ? "RUN_FINISHED=1"
                            : (result.timedOut ? "shell timed out" : "RUN_FINISHED=0"));
            activeRunId = null;
            synchronized (stateLock) {
                busy = false;
                publishLocked();
            }
            mainHandler.postDelayed(this::loadPreflight, 2500L);
        });
    }

    public void importPayload(Uri uri, String displayName) {
        if (!beginBusyOperation(false)) {
            return;
        }
        appendLine("--- 导入自定义 SO ---");
        executor.execute(() -> {
            JinghuRunner.PayloadImportResult result = runner.importPayload(uri, displayName);
            appendLine(result.message);
            boolean imported = result.success;
            synchronized (stateLock) {
                if (imported) {
                    refreshPayloadLocked();
                    snapshot = null;
                }
                busy = false;
                publishLocked();
            }
            if (imported) {
                appendLine("PAYLOAD_PERSISTED=1 应用私有存储已更新");
            }
        });
    }

    public void restoreBundledPayload() {
        synchronized (stateLock) {
            if (busy) {
                return;
            }
            runner.clearCustomPayload();
            refreshPayloadLocked();
            snapshot = null;
            publishLocked();
        }
        appendLine("PAYLOAD_SELECTED=bundled-v20");
    }

    public void loadSavedLogs() {
        executor.execute(() -> savedLogsEvent.postValue(
                new Event<>(logStore.readLatestLogs(32000))));
    }

    public void recordUiEvent(String line) {
        appendLine(line);
    }

    private JinghuRunner.ShellResult installManagerBeforePayload() {
        if (!runner.verifyLocalAsset(JinghuRunner.MANAGER_ASSET,
                JinghuRunner.EXPECTED_MANAGER_SHA256)) {
            return error("APP_ERROR=Manager 内置哈希不匹配");
        }
        JinghuRunner.ShellResult managerCopy = runner.copyAsset(
                JinghuRunner.MANAGER_ASSET, JinghuRunner.MANAGER_REMOTE);
        if (managerCopy.exitCode != 0
                || !managerCopy.contains(JinghuRunner.EXPECTED_MANAGER_SHA256)) {
            return new JinghuRunner.ShellResult(
                    merge(managerCopy.lines, "APP_ERROR=Manager 远端哈希校验失败"), -1, false);
        }
        appendLines(managerCopy.lines);
        JinghuRunner.ShellResult install = runner.installManager(null);
        if (install.exitCode != 0) {
            return new JinghuRunner.ShellResult(
                    merge(install.lines, "APP_ERROR=Manager 安装失败，未执行 payload"), -1, false);
        }
        appendLines(install.lines);
        return install;
    }

    private boolean beginBusyOperation(boolean requireShizuku) {
        synchronized (stateLock) {
            if (busy || (requireShizuku && shizukuState != ShizukuState.AUTHORIZED)) {
                return false;
            }
            busy = true;
            publishLocked();
            return true;
        }
    }

    private void finishBusyOperation() {
        synchronized (stateLock) {
            busy = false;
            publishLocked();
        }
    }

    private void refreshPayloadLocked() {
        payloadName = runner.getPayloadDisplayName();
        payloadSha256 = runner.getPayloadSha256();
        defaultPayload = runner.isDefaultPayload();
    }

    private void appendResult(JinghuRunner.ShellResult result, boolean streamed) {
        if (!streamed) {
            appendLines(result.lines);
        }
        appendLine("exit=" + result.exitCode + (result.timedOut ? " timed_out=1" : ""));
    }

    private void appendLines(Iterable<String> lines) {
        for (String line : lines) {
            appendLine(line);
        }
    }

    private void appendLine(String line) {
        String value = line == null ? "" : line;
        String runId = activeRunId;
        if (runId != null) {
            logStore.append(runId, value);
        } else {
            logStore.appendEvent(value);
        }
        synchronized (stateLock) {
            appendLineLocked(value);
            publishLocked();
        }
    }

    private void appendLineLocked(String value) {
        String waiting = getApplication().getString(R.string.output_waiting);
        if (waiting.equals(output)) {
            output = "";
        }
        output += (output.isEmpty() ? "" : "\n") + value;
        if (output.length() > 24000) {
            output = output.substring(output.length() - 24000);
        }
    }

    private JinghuRunner.ShellResult safeRun(Task task) {
        try {
            return task.run();
        } catch (Exception e) {
            return error("APP_ERROR=" + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private UiState buildStateLocked() {
        return new UiState(shizukuState, snapshot, busy, output,
                payloadName, payloadSha256, defaultPayload);
    }

    private void publishLocked() {
        UiState value = buildStateLocked();
        if (Looper.myLooper() == Looper.getMainLooper()) {
            uiState.setValue(value);
        } else {
            uiState.postValue(value);
        }
    }

    private static JinghuRunner.ShellResult error(String line) {
        return new JinghuRunner.ShellResult(Collections.singletonList(line), -1, false);
    }

    private static List<String> merge(Iterable<String> lines, String extra) {
        List<String> result = new ArrayList<>();
        for (String line : lines) {
            result.add(line);
        }
        result.add(extra);
        return result;
    }

    @Override
    protected void onCleared() {
        mainHandler.removeCallbacksAndMessages(null);
        executor.shutdownNow();
        runner.close();
    }

    private interface Task {
        JinghuRunner.ShellResult run();
    }
}
