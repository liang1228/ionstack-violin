package com.zeoon3.jinghu;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Marks an unfinished payload journal when Android broadcasts a completed boot. */
public final class BootReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(Context context, Intent intent) {
        if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
            new RunLogStore(context).recoverAfterBoot();
        }
    }
}
