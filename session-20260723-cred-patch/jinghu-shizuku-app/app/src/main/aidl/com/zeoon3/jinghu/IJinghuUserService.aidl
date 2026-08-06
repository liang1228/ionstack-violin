package com.zeoon3.jinghu;

import android.os.ParcelFileDescriptor;

interface IJinghuUserService {
    void destroy() = 16777114;

    int execute(String command, in ParcelFileDescriptor output, long timeoutMillis) = 1;

    int copyToRemote(in ParcelFileDescriptor source, String remotePath,
            in ParcelFileDescriptor output, long timeoutMillis) = 2;
}
