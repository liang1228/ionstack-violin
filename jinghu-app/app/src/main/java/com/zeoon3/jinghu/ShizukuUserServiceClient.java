package com.zeoon3.jinghu;

import android.content.ComponentName;
import android.content.Context;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import rikka.shizuku.Shizuku;

/** Lifecycle-independent client for the Shizuku UserService binder. */
final class ShizukuUserServiceClient implements AutoCloseable {
    static final class Result {
        final List<String> lines;
        final int exitCode;
        final boolean timedOut;

        Result(List<String> lines, int exitCode) {
            this.lines = Collections.unmodifiableList(new ArrayList<>(lines));
            this.exitCode = exitCode;
            timedOut = exitCode == JinghuUserService.TIMEOUT_EXIT_CODE;
        }
    }

    private static final long BIND_TIMEOUT_SECONDS = 12L;

    private final Object serviceLock = new Object();
    private final Shizuku.UserServiceArgs serviceArgs;
    private final ServiceConnection serviceConnection;

    private IJinghuUserService service;
    private CountDownLatch connectionLatch = new CountDownLatch(0);
    private boolean bindingRequested;

    ShizukuUserServiceClient(Context context) {
        serviceArgs = new Shizuku.UserServiceArgs(new ComponentName(
                context.getPackageName(), JinghuUserService.class.getName()))
                .daemon(false)
                .processNameSuffix("jinghu_service")
                .debuggable((context.getApplicationInfo().flags
                        & ApplicationInfo.FLAG_DEBUGGABLE) != 0)
                .version(readVersionCode(context));
        serviceConnection = new ServiceConnection() {
            @Override
            public void onServiceConnected(ComponentName name, IBinder binder) {
                synchronized (serviceLock) {
                    service = binder != null && binder.pingBinder()
                            ? IJinghuUserService.Stub.asInterface(binder) : null;
                    connectionLatch.countDown();
                }
            }

            @Override
            public void onServiceDisconnected(ComponentName name) {
                synchronized (serviceLock) {
                    service = null;
                    bindingRequested = false;
                    connectionLatch.countDown();
                }
            }
        };
    }

    private static int readVersionCode(Context context) {
        try {
            PackageInfo info = context.getPackageManager().getPackageInfo(
                    context.getPackageName(), 0);
            long version = info.getLongVersionCode();
            return (int) Math.min(Integer.MAX_VALUE, Math.max(1L, version));
        } catch (PackageManager.NameNotFoundException e) {
            return 1;
        }
    }

    Result execute(String command, long timeoutSeconds, JinghuRunner.LineSink sink) {
        List<String> lines = Collections.synchronizedList(new ArrayList<>());
        try {
            IJinghuUserService remote = requireService();
            ParcelFileDescriptor[] outputPipe = ParcelFileDescriptor.createPipe();
            Thread reader = startReader(outputPipe[0], lines, sink);
            int exitCode;
            try {
                exitCode = remote.execute(command, outputPipe[1],
                        TimeUnit.SECONDS.toMillis(timeoutSeconds));
            } finally {
                closeQuietly(outputPipe[1]);
            }
            joinReader(reader, lines);
            return new Result(lines, exitCode);
        } catch (Exception e) {
            lines.add(errorLine(e));
            invalidateRemote();
            return new Result(lines, JinghuUserService.SERVICE_ERROR_EXIT_CODE);
        }
    }

    Result copyToRemote(InputStream source, String remotePath, long timeoutSeconds) {
        List<String> lines = Collections.synchronizedList(new ArrayList<>());
        ParcelFileDescriptor[] sourcePipe = null;
        ParcelFileDescriptor[] outputPipe = null;
        Thread writer = null;
        Thread reader = null;
        try {
            IJinghuUserService remote = requireService();
            sourcePipe = ParcelFileDescriptor.createPipe();
            outputPipe = ParcelFileDescriptor.createPipe();
            writer = startWriter(source, sourcePipe[1], lines);
            reader = startReader(outputPipe[0], lines, null);
            int exitCode;
            try {
                exitCode = remote.copyToRemote(sourcePipe[0], remotePath, outputPipe[1],
                        TimeUnit.SECONDS.toMillis(timeoutSeconds));
            } finally {
                closeQuietly(sourcePipe[0]);
                closeQuietly(outputPipe[1]);
            }
            joinWorker(writer, "input writer", lines);
            joinReader(reader, lines);
            return new Result(lines, exitCode);
        } catch (Exception e) {
            lines.add(errorLine(e));
            invalidateRemote();
            return new Result(lines, JinghuUserService.SERVICE_ERROR_EXIT_CODE);
        } finally {
            closeQuietly(source);
            closePipe(sourcePipe);
            closePipe(outputPipe);
            if (writer != null && writer.isAlive()) {
                writer.interrupt();
            }
            if (reader != null && reader.isAlive()) {
                reader.interrupt();
            }
        }
    }

    private IJinghuUserService requireService() throws Exception {
        CountDownLatch latch;
        boolean shouldBind = false;
        synchronized (serviceLock) {
            if (isRemoteAliveLocked()) {
                return service;
            }
            service = null;
            if (!bindingRequested) {
                bindingRequested = true;
                connectionLatch = new CountDownLatch(1);
                shouldBind = true;
            }
            latch = connectionLatch;
        }

        if (shouldBind) {
            try {
                Shizuku.bindUserService(serviceArgs, serviceConnection);
            } catch (RuntimeException e) {
                synchronized (serviceLock) {
                    bindingRequested = false;
                    connectionLatch.countDown();
                }
                throw e;
            }
        }
        if (!latch.await(BIND_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            throw new IOException("Shizuku UserService connection timed out");
        }
        synchronized (serviceLock) {
            if (!isRemoteAliveLocked()) {
                bindingRequested = false;
                throw new IOException("Shizuku UserService binder unavailable");
            }
            return service;
        }
    }

    private boolean isRemoteAliveLocked() {
        return service != null && service.asBinder().pingBinder();
    }

    private void invalidateRemote() {
        synchronized (serviceLock) {
            if (service != null && !service.asBinder().pingBinder()) {
                service = null;
                bindingRequested = false;
            }
        }
    }

    private static Thread startReader(ParcelFileDescriptor descriptor, List<String> lines,
                                      JinghuRunner.LineSink sink) {
        Thread thread = new Thread(() -> {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new ParcelFileDescriptor.AutoCloseInputStream(descriptor),
                    StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line);
                    if (sink != null) {
                        sink.onLine(line);
                    }
                }
            } catch (IOException e) {
                lines.add("APP_OUTPUT_ERROR=" + String.valueOf(e.getMessage()));
            }
        }, "jinghu-user-service-reader");
        thread.start();
        return thread;
    }

    private static Thread startWriter(InputStream source, ParcelFileDescriptor descriptor,
                                      List<String> lines) {
        Thread thread = new Thread(() -> {
            try (InputStream input = source;
                 OutputStream output = new ParcelFileDescriptor.AutoCloseOutputStream(descriptor)) {
                byte[] buffer = new byte[64 * 1024];
                int count;
                while ((count = input.read(buffer)) != -1) {
                    output.write(buffer, 0, count);
                }
                output.flush();
            } catch (IOException e) {
                lines.add("APP_INPUT_ERROR=" + String.valueOf(e.getMessage()));
            }
        }, "jinghu-user-service-writer");
        thread.start();
        return thread;
    }

    private static void joinReader(Thread reader, List<String> lines)
            throws InterruptedException {
        joinWorker(reader, "output reader", lines);
    }

    private static void joinWorker(Thread thread, String label, List<String> lines)
            throws InterruptedException {
        thread.join(5000L);
        if (thread.isAlive()) {
            thread.interrupt();
            lines.add("APP_ERROR=UserService " + label + " did not stop");
        }
    }

    private static String errorLine(Exception e) {
        String name = e instanceof RemoteException ? "RemoteException"
                : e.getClass().getSimpleName();
        return "APP_ERROR=Shizuku UserService " + name + ": "
                + String.valueOf(e.getMessage());
    }

    private static void closePipe(ParcelFileDescriptor[] pipe) {
        if (pipe == null) {
            return;
        }
        for (ParcelFileDescriptor descriptor : pipe) {
            closeQuietly(descriptor);
        }
    }

    private static void closeQuietly(ParcelFileDescriptor descriptor) {
        if (descriptor == null) {
            return;
        }
        try {
            descriptor.close();
        } catch (IOException ignored) {
            // Best-effort cleanup after a Binder operation.
        }
    }

    private static void closeQuietly(InputStream input) {
        if (input == null) {
            return;
        }
        try {
            input.close();
        } catch (IOException ignored) {
            // The source may already have been closed by the writer thread.
        }
    }

    @Override
    public void close() {
        boolean shouldUnbind;
        synchronized (serviceLock) {
            shouldUnbind = bindingRequested;
            service = null;
            bindingRequested = false;
            connectionLatch.countDown();
        }
        if (shouldUnbind && Shizuku.pingBinder()) {
            try {
                Shizuku.unbindUserService(serviceArgs, serviceConnection, true);
            } catch (RuntimeException ignored) {
                // Shizuku may disappear while the app is being torn down.
            }
        }
    }
}
