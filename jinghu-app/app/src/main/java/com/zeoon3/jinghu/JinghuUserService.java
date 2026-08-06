package com.zeoon3.jinghu;

import android.content.Context;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.system.Os;

import androidx.annotation.Keep;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/** Shell-UID process hosted by Shizuku's supported UserService API. */
public final class JinghuUserService extends IJinghuUserService.Stub {
    static final int TIMEOUT_EXIT_CODE = -124;
    static final int SERVICE_ERROR_EXIT_CODE = -125;

    private static final long MAX_TRANSFER_BYTES = 64L * 1024L * 1024L;
    private static final Pattern REMOTE_PATH = Pattern.compile(
            "^/data/local/tmp/[A-Za-z0-9._-]+$");

    public JinghuUserService() {
    }

    @Keep
    public JinghuUserService(Context context) {
        // Shizuku API 13 creates UserService instances with a package context.
    }

    @Override
    public void destroy() {
        System.exit(0);
    }

    @Override
    public int execute(String command, ParcelFileDescriptor output, long timeoutMillis) {
        try (OutputStream target = new ParcelFileDescriptor.AutoCloseOutputStream(output)) {
            try {
                if (command == null || command.isEmpty()) {
                    writeLine(target, "USER_SERVICE_ERROR=empty command");
                    return SERVICE_ERROR_EXIT_CODE;
                }
                return runProcess(command, target, boundedTimeout(timeoutMillis));
            } catch (Exception e) {
                writeLine(target, errorLine(e));
                return SERVICE_ERROR_EXIT_CODE;
            }
        } catch (IOException e) {
            closeQuietly(output);
            return SERVICE_ERROR_EXIT_CODE;
        }
    }

    @Override
    public int copyToRemote(ParcelFileDescriptor source, String remotePath,
                            ParcelFileDescriptor output, long timeoutMillis) {
        File partial = remotePath == null ? null
                : new File(remotePath + ".part-" + Process.myPid());
        try (InputStream input = new ParcelFileDescriptor.AutoCloseInputStream(source);
             OutputStream target = new ParcelFileDescriptor.AutoCloseOutputStream(output)) {
            try {
                if (remotePath == null || !REMOTE_PATH.matcher(remotePath).matches()) {
                    writeLine(target, "USER_SERVICE_ERROR=invalid remote path");
                    return SERVICE_ERROR_EXIT_CODE;
                }

                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                long deadlineNanos = System.nanoTime()
                        + TimeUnit.MILLISECONDS.toNanos(boundedTimeout(timeoutMillis));
                long transferred = 0L;
                byte[] buffer = new byte[64 * 1024];
                try (FileOutputStream fileOutput = new FileOutputStream(partial)) {
                    int count;
                    while ((count = input.read(buffer)) != -1) {
                        transferred += count;
                        if (transferred > MAX_TRANSFER_BYTES) {
                            throw new IOException("payload exceeds 64 MiB limit");
                        }
                        if (System.nanoTime() > deadlineNanos) {
                            writeLine(target, "USER_SERVICE_ERROR=transfer timed out");
                            return TIMEOUT_EXIT_CODE;
                        }
                        digest.update(buffer, 0, count);
                        fileOutput.write(buffer, 0, count);
                    }
                    fileOutput.flush();
                    fileOutput.getFD().sync();
                }

                Os.chmod(partial.getAbsolutePath(), 0700);
                Os.rename(partial.getAbsolutePath(), remotePath);
                writeLine(target, toHex(digest.digest()) + "  " + remotePath);
                return 0;
            } catch (Exception e) {
                writeLine(target, errorLine(e));
                return SERVICE_ERROR_EXIT_CODE;
            }
        } catch (IOException e) {
            return SERVICE_ERROR_EXIT_CODE;
        } finally {
            if (partial != null && partial.isFile()) {
                //noinspection ResultOfMethodCallIgnored
                partial.delete();
            }
            closeQuietly(source);
            closeQuietly(output);
        }
    }

    private static int runProcess(String command, OutputStream output, long timeoutMillis)
            throws IOException, InterruptedException {
        java.lang.Process process = new ProcessBuilder("/system/bin/sh", "-c", command)
                .directory(new File("/"))
                .redirectErrorStream(true)
                .start();
        process.getOutputStream().close();

        AtomicReference<IOException> outputError = new AtomicReference<>();
        Thread reader = new Thread(() -> {
            try (InputStream input = new BufferedInputStream(process.getInputStream())) {
                byte[] buffer = new byte[16 * 1024];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    output.write(buffer, 0, count);
                    output.flush();
                }
            } catch (IOException e) {
                outputError.set(e);
            }
        }, "jinghu-user-service-output");
        reader.start();

        boolean finished = process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS);
        if (!finished) {
            process.destroy();
            if (!process.waitFor(2L, TimeUnit.SECONDS)) {
                process.destroyForcibly();
            }
        }
        reader.join(5000L);
        if (reader.isAlive()) {
            reader.interrupt();
        }
        IOException readerFailure = outputError.get();
        if (readerFailure != null) {
            throw readerFailure;
        }
        return finished ? process.exitValue() : TIMEOUT_EXIT_CODE;
    }

    private static long boundedTimeout(long timeoutMillis) {
        return Math.max(1000L, Math.min(timeoutMillis, TimeUnit.MINUTES.toMillis(5L)));
    }

    private static void writeLine(OutputStream output, String line) throws IOException {
        output.write((line + "\n").getBytes(StandardCharsets.UTF_8));
        output.flush();
    }

    private static String errorLine(Exception error) {
        return "USER_SERVICE_ERROR=" + error.getClass().getSimpleName()
                + ": " + String.valueOf(error.getMessage());
    }

    private static void closeQuietly(ParcelFileDescriptor descriptor) {
        if (descriptor == null) {
            return;
        }
        try {
            descriptor.close();
        } catch (IOException ignored) {
            // Best-effort descriptor cleanup in the remote process.
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            result.append(String.format(Locale.ROOT, "%02x", value));
        }
        return result.toString();
    }
}
