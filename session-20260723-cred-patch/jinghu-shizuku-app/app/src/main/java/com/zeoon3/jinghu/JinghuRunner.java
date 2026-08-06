package com.zeoon3.jinghu;

import android.content.Context;
import android.content.res.AssetManager;
import android.net.Uri;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Properties;

/** The device-side execution boundary for the Jinghu v20 app. */
public final class JinghuRunner {
    public static final String EXPECTED_KERNEL =
            "6.6.77-android15-8-g5770c661275f-abogki443185593-4k";
    public static final String PAYLOAD_ASSET =
            "preload_jinghu_v20_final_optimization.so";
    public static final String MANAGER_ASSET = "KernelSU_v3.2.5_32525-release.apk";
    public static final String PAYLOAD_REMOTE =
            "/data/local/tmp/preload_jinghu_v20_final_optimization.so";
    public static final String MANAGER_REMOTE =
            "/data/local/tmp/KernelSU_v3.2.5_32525-release.apk";
    public static final String EXPECTED_PAYLOAD_SHA256 =
            "016477c1b9ae3cdc15f2b5b68bc51d69614aca994847cf80f2970ebdb7007463";
    public static final String EXPECTED_MANAGER_SHA256 =
            "1417081413bf7ab1de8e440ecbcb62685037c8f28f048f0f8b79e305b31ab916";

    private static final String SELECTED_PAYLOAD_FILE = "selected-payload.so";
    private static final String SELECTED_PAYLOAD_META = "selected-payload.properties";
    private static final long PREFLIGHT_TIMEOUT_SECONDS = 15L;
    private static final long TRANSFER_TIMEOUT_SECONDS = 90L;
    private static final long RUN_TIMEOUT_SECONDS = 180L;

    public interface LineSink {
        void onLine(String line);
    }

    public static final class ShellResult {
        public final List<String> lines;
        public final int exitCode;
        public final boolean timedOut;

        ShellResult(List<String> lines, int exitCode, boolean timedOut) {
            this.lines = Collections.unmodifiableList(new ArrayList<>(lines));
            this.exitCode = exitCode;
            this.timedOut = timedOut;
        }

        public String text() {
            return String.join("\n", lines);
        }

        public boolean contains(String value) {
            return text().contains(value);
        }
    }

    public static final class PayloadImportResult {
        public final boolean success;
        public final String message;
        public final String sha256;
        public final long size;

        PayloadImportResult(boolean success, String message, String sha256, long size) {
            this.success = success;
            this.message = message;
            this.sha256 = sha256;
            this.size = size;
        }
    }

    private final Context context;
    private final AssetManager assets;
    private final ShizukuUserServiceClient serviceClient;
    private final File selectedPayloadFile;
    private final File selectedPayloadMeta;
    private String selectedPayloadName;
    private String selectedPayloadSha256;

    public JinghuRunner(Context context) {
        this.context = context.getApplicationContext();
        assets = this.context.getAssets();
        serviceClient = new ShizukuUserServiceClient(this.context);
        selectedPayloadFile = new File(this.context.getFilesDir(), SELECTED_PAYLOAD_FILE);
        selectedPayloadMeta = new File(this.context.getFilesDir(), SELECTED_PAYLOAD_META);
        loadSelectedPayload();
    }

    public synchronized boolean isDefaultPayload() {
        return selectedPayloadName == null;
    }

    public synchronized String getPayloadDisplayName() {
        return isDefaultPayload() ? PAYLOAD_ASSET : selectedPayloadName;
    }

    public synchronized String getPayloadSha256() {
        return isDefaultPayload() ? EXPECTED_PAYLOAD_SHA256 : selectedPayloadSha256;
    }

    /** Imports and persists an arm64 ELF shared object selected through ACTION_OPEN_DOCUMENT. */
    public synchronized PayloadImportResult importPayload(Uri uri, String displayName) {
        if (uri == null) {
            return failure("APP_ERROR=未选择 SO 文件");
        }
        File temp = new File(context.getFilesDir(), SELECTED_PAYLOAD_FILE + ".tmp");
        long size = 0L;
        String sha256;
        try (InputStream input = context.getContentResolver().openInputStream(uri);
             OutputStream output = new FileOutputStream(temp)) {
            if (input == null) {
                //noinspection ResultOfMethodCallIgnored
                temp.delete();
                return failure("APP_ERROR=无法读取所选文件");
            }
            MessageDigest digest = sha256Digest();
            byte[] header = new byte[20];
            int headerSize = 0;
            byte[] buffer = new byte[64 * 1024];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (headerSize < header.length) {
                    int copy = Math.min(count, header.length - headerSize);
                    System.arraycopy(buffer, 0, header, headerSize, copy);
                    headerSize += copy;
                }
                digest.update(buffer, 0, count);
                output.write(buffer, 0, count);
                size += count;
            }
            output.flush();
            sha256 = toHex(digest.digest());
            if (!isArm64Elf(header, headerSize, size)) {
                //noinspection ResultOfMethodCallIgnored
                temp.delete();
                return failure("APP_ERROR=所选文件不是有效的 arm64 ELF SO");
            }
        } catch (Exception e) {
            //noinspection ResultOfMethodCallIgnored
            temp.delete();
            return failure("APP_ERROR=导入 SO 失败：" + e.getClass().getSimpleName()
                    + ": " + e.getMessage());
        }

        String safeName = safe(displayName == null || displayName.isEmpty()
                ? "selected-payload.so" : displayName);
        try {
            if (!temp.renameTo(selectedPayloadFile)) {
                throw new IOException("cannot replace selected payload");
            }
            Properties properties = new Properties();
            properties.setProperty("name", safeName);
            properties.setProperty("sha256", sha256);
            properties.setProperty("size", Long.toString(size));
            properties.setProperty("selected_at", Long.toString(System.currentTimeMillis()));
            writeSelectedMetadata(properties);
            selectedPayloadName = safeName;
            selectedPayloadSha256 = sha256;
            return new PayloadImportResult(true,
                    "PAYLOAD_IMPORTED=1 size=" + size + " sha256=" + sha256,
                    sha256, size);
        } catch (Exception e) {
            //noinspection ResultOfMethodCallIgnored
            selectedPayloadFile.delete();
            //noinspection ResultOfMethodCallIgnored
            temp.delete();
            return failure("APP_ERROR=保存自定义 SO 失败：" + e.getMessage());
        }
    }

    public synchronized void clearCustomPayload() {
        //noinspection ResultOfMethodCallIgnored
        selectedPayloadFile.delete();
        //noinspection ResultOfMethodCallIgnored
        selectedPayloadMeta.delete();
        selectedPayloadName = null;
        selectedPayloadSha256 = null;
    }

    public synchronized boolean verifySelectedPayload() {
        if (isDefaultPayload()) {
            return verifyLocalAsset(PAYLOAD_ASSET, EXPECTED_PAYLOAD_SHA256);
        }
        if (!selectedPayloadFile.isFile() || selectedPayloadSha256 == null) {
            return false;
        }
        try {
            return isArm64Elf(selectedPayloadFile)
                    && selectedPayloadSha256.equalsIgnoreCase(sha256File(selectedPayloadFile));
        } catch (IOException | NoSuchAlgorithmException e) {
            return false;
        }
    }

    public ShellResult preflight() {
        String command = String.join("\n",
                "echo BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)",
                "echo DEVICE=$(getprop ro.product.device)",
                "echo MODEL=$(getprop ro.product.model)",
                "echo KERNEL=$(uname -r)",
                "echo SDK=$(getprop ro.build.version.sdk)",
                "echo ENFORCE=$(getenforce 2>/dev/null)",
                "echo BOOT_COMPLETED=$(getprop sys.boot_completed)",
                "echo KSU_MODULE=$(grep -c '^kernelsu ' /proc/modules 2>/dev/null)",
                "B=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)",
                "if [ -n \"$B\" ] && [ -e \"/data/local/tmp/.jinghu-v20-$B\" ]; then "
                        + "echo MARKER=1; else echo MARKER=0; fi",
                "echo PAYLOAD_SHA256=$(sha256sum " + PAYLOAD_REMOTE + " 2>/dev/null)",
                "echo MANAGER_PACKAGE=$(pm path com.zeoon3.jinghu 2>/dev/null)");
        return execute(command, PREFLIGHT_TIMEOUT_SECONDS, null);
    }

    /** Streams a bundled asset to a shell-owned path and verifies the resulting remote hash. */
    public ShellResult copyAsset(String assetName, String remotePath) {
        try (InputStream input = assets.open(assetName, AssetManager.ACCESS_STREAMING)) {
            return copyStream(input, remotePath);
        } catch (Exception e) {
            return errorResult(e);
        }
    }

    /** Streams the selected bundled/custom payload to the fixed device path. */
    public synchronized ShellResult copySelectedPayload(String remotePath) {
        try (InputStream input = openSelectedPayload()) {
            return copyStream(input, remotePath);
        } catch (Exception e) {
            return errorResult(e);
        }
    }

    public ShellResult installManager(LineSink sink) {
        return execute("pm install -r '" + MANAGER_REMOTE + "' 2>&1",
                TRANSFER_TIMEOUT_SECONDS, sink);
    }

    /**
     * Runs the fixed v20 sequence. The remote marker is keyed by the current boot ID,
     * so a second tap in the same boot is rejected on-device as well as in the UI.
     */
    public ShellResult runPayload(LineSink sink) {
        String command = String.join("\n",
                "set +e",
                "SO='" + PAYLOAD_REMOTE + "'",
                "BOOT_ID=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)",
                "MARKER=\"/data/local/tmp/.jinghu-v20-$BOOT_ID\"",
                "echo RUN_BOOT_ID=$BOOT_ID",
                "if [ \"$(uname -r)\" != \"" + EXPECTED_KERNEL + "\" ]; then",
                "  echo STOP_KERNEL_MISMATCH=$(uname -r)",
                "  exit 20",
                "fi",
                "if [ \"$(getprop sys.boot_completed)\" != \"1\" ]; then",
                "  echo STOP_BOOT_NOT_COMPLETED=$(getprop sys.boot_completed)",
                "  exit 21",
                "fi",
                "if [ \"$(getenforce 2>/dev/null)\" != \"Enforcing\" ]; then",
                "  echo STOP_SELINUX=$(getenforce 2>/dev/null)",
                "  exit 22",
                "fi",
                "if [ -e \"$MARKER\" ]; then",
                "  echo STOP_ALREADY_EXECUTED=1",
                "  exit 23",
                "fi",
                "if [ ! -s \"$SO\" ]; then",
                "  echo STOP_PAYLOAD_MISSING=1",
                "  exit 24",
                "fi",
                "echo PAYLOAD_SHA256=$(sha256sum \"$SO\" 2>/dev/null)",
                "touch \"$MARKER\"",
                "echo MARKER_CREATED=1",
                "echo PAYLOAD_MODE=V20_FINAL_OPTIMIZATION",
                "echo PAYLOAD_BEGIN=1",
                "LD_PRELOAD=\"$SO\" /system/bin/true 2>&1",
                "PAYLOAD_EXIT=$?",
                "echo PAYLOAD_EXIT=$PAYLOAD_EXIT",
                "sleep 2",
                "echo ENFORCE=$(getenforce 2>/dev/null)",
                "echo ENFORCE_VALUE=$(cat /sys/fs/selinux/enforce 2>/dev/null)",
                "echo BOOT_COMPLETED=$(getprop sys.boot_completed)",
                "echo KSU_MODULE=$(grep -c '^kernelsu ' /proc/modules 2>/dev/null)",
                "echo BOOT_ID_AFTER=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null)",
                "echo SERVICES=$(service list 2>/dev/null | wc -l)",
                "echo SURFACEFLINGER=$(pidof surfaceflinger 2>/dev/null)",
                "if [ -x /data/adb/ksud ]; then",
                "  /data/adb/ksud debug info 2>&1",
                "elif command -v ksud >/dev/null 2>&1; then",
                "  ksud debug info 2>&1",
                "else",
                "  echo KSUD=not-found",
                "fi",
                "echo SU_CHECK_BEGIN=1",
                "if [ -x /system/bin/su ]; then /system/bin/su -c 'id -Z; id' 2>&1; else echo SU=not-found; fi",
                "echo IP_PING_BEGIN=1",
                "ping -c 1 -W 3 223.5.5.5 2>&1 | tail -4",
                "echo DNS_PING_BEGIN=1",
                "ping -c 1 -W 3 www.qq.com 2>&1 | tail -6",
                "FINAL_ENFORCE=$(getenforce 2>/dev/null)",
                "FINAL_ENFORCE_VALUE=$(cat /sys/fs/selinux/enforce 2>/dev/null)",
                "FINAL_KSU=$(grep -c '^kernelsu ' /proc/modules 2>/dev/null)",
                "FINAL_SU=$(if [ -x /system/bin/su ]; then /system/bin/su -c id 2>/dev/null; fi)",
                "if [ \"$PAYLOAD_EXIT\" = \"0\" ] && [ \"$FINAL_ENFORCE\" = \"Enforcing\" ] && [ \"$FINAL_ENFORCE_VALUE\" = \"1\" ] && [ \"$FINAL_KSU\" = \"1\" ] && echo \"$FINAL_SU\" | grep -q \"uid=0\"; then",
                "  echo RUN_FINISHED=1",
                "else",
                "  echo RUN_FINISHED=0",
                "fi");
        return execute(command, RUN_TIMEOUT_SECONDS, sink);
    }

    public boolean verifyLocalAsset(String assetName, String expectedSha256) {
        try (InputStream input = assets.open(assetName, AssetManager.ACCESS_STREAMING)) {
            return expectedSha256.equalsIgnoreCase(sha256Input(input));
        } catch (IOException | NoSuchAlgorithmException e) {
            return false;
        }
    }

    private synchronized InputStream openSelectedPayload() throws IOException {
        if (isDefaultPayload()) {
            return assets.open(PAYLOAD_ASSET, AssetManager.ACCESS_STREAMING);
        }
        return new FileInputStream(selectedPayloadFile);
    }

    private ShellResult copyStream(InputStream input, String remotePath) {
        ShizukuUserServiceClient.Result result = serviceClient.copyToRemote(
                input, remotePath, TRANSFER_TIMEOUT_SECONDS);
        return new ShellResult(result.lines, result.exitCode, result.timedOut);
    }

    private ShellResult execute(String command, long timeoutSeconds, LineSink sink) {
        ShizukuUserServiceClient.Result result = serviceClient.execute(
                command, timeoutSeconds, sink);
        return new ShellResult(result.lines, result.exitCode, result.timedOut);
    }

    public void close() {
        serviceClient.close();
    }

    private void loadSelectedPayload() {
        if (!selectedPayloadFile.isFile() || !selectedPayloadMeta.isFile()) {
            selectedPayloadName = null;
            selectedPayloadSha256 = null;
            return;
        }
        Properties properties = new Properties();
        try (FileInputStream input = new FileInputStream(selectedPayloadMeta)) {
            properties.load(input);
            String name = properties.getProperty("name", "");
            String sha = properties.getProperty("sha256", "");
            if (name.isEmpty() || !sha.matches("[0-9a-fA-F]{64}")) {
                clearCustomPayload();
                return;
            }
            selectedPayloadName = name;
            selectedPayloadSha256 = sha.toLowerCase(Locale.ROOT);
        } catch (IOException e) {
            clearCustomPayload();
        }
    }

    private void writeSelectedMetadata(Properties properties) throws IOException {
        File temp = new File(context.getFilesDir(), SELECTED_PAYLOAD_META + ".tmp");
        try (OutputStreamWriter writer = new OutputStreamWriter(
                new FileOutputStream(temp), StandardCharsets.UTF_8)) {
            properties.store(writer, "Jinghu selected payload");
        }
        if (!temp.renameTo(selectedPayloadMeta)) {
            throw new IOException("cannot replace selected payload metadata");
        }
    }

    private static boolean isArm64Elf(File file) throws IOException {
        try (InputStream input = new FileInputStream(file)) {
            byte[] header = new byte[20];
            int count = readHeader(input, header);
            return isArm64Elf(header, count, file.length());
        }
    }

    private static boolean isArm64Elf(byte[] header, int count, long size) {
        if (size < 64 || count < 20) {
            return false;
        }
        boolean magic = (header[0] & 0xff) == 0x7f
                && header[1] == 'E' && header[2] == 'L' && header[3] == 'F';
        int machine = (header[18] & 0xff) | ((header[19] & 0xff) << 8);
        return magic && header[4] == 2 && header[5] == 1 && machine == 183;
    }

    private static int readHeader(InputStream input, byte[] header) throws IOException {
        int offset = 0;
        int count;
        while (offset < header.length
                && (count = input.read(header, offset, header.length - offset)) != -1) {
            offset += count;
        }
        return offset;
    }

    private static String sha256File(File file) throws IOException, NoSuchAlgorithmException {
        try (InputStream input = new FileInputStream(file)) {
            return sha256Input(input);
        }
    }

    private static String sha256Input(InputStream input)
            throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = sha256Digest();
        byte[] buffer = new byte[64 * 1024];
        int count;
        while ((count = input.read(buffer)) != -1) {
            digest.update(buffer, 0, count);
        }
        return toHex(digest.digest());
    }

    private static MessageDigest sha256Digest() throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-256");
    }

    private static PayloadImportResult failure(String message) {
        return new PayloadImportResult(false, message, "", 0L);
    }

    private static ShellResult errorResult(Exception e) {
        return new ShellResult(Collections.singletonList(
                "APP_ERROR=" + e.getClass().getSimpleName() + ": " + e.getMessage()), -1, false);
    }

    private static String safe(String value) {
        return value == null ? "" : value.replace('\n', ' ').replace('\r', ' ');
    }

    private static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format(Locale.ROOT, "%02x", value));
        }
        return result.toString();
    }
}
