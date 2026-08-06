package com.violin.injector

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*

class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != Intent.ACTION_LOCKED_BOOT_COMPLETED) return

        val configManager = ConfigManager.getInstance(context)
        if (!configManager.bootAutoRun) return

        val notificationManager =
            context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        createNotificationChannel(notificationManager)

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle("Violin Root")
            .setContentText("正在执行开机自启动...")
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .build()
        notificationManager.notify(NOTIFICATION_ID, notification)

        val pendingResult = goAsync()
        CoroutineScope(Dispatchers.IO).launch {
            try {
                executeBootSequence(context, configManager)
                notificationManager.notify(NOTIFICATION_ID,
                    NotificationCompat.Builder(context, CHANNEL_ID)
                        .setSmallIcon(android.R.drawable.ic_dialog_info)
                        .setContentTitle("Violin Root")
                        .setContentText("开机自启动完成")
                        .setAutoCancel(true)
                        .build()
                )
            } catch (e: Exception) {
                notificationManager.notify(NOTIFICATION_ID,
                    NotificationCompat.Builder(context, CHANNEL_ID)
                        .setSmallIcon(android.R.drawable.ic_dialog_info)
                        .setContentTitle("Violin Root")
                        .setContentText("开机自启动失败: ${e.message}")
                        .setAutoCancel(true)
                        .build()
                )
            } finally {
                pendingResult.finish()
            }
        }
    }

    private suspend fun executeBootSequence(context: Context, configManager: ConfigManager) {
        val shizukuManager = ShizukuManager(context)

        if (!shizukuManager.isServiceAvailable()) throw Exception("Shizuku not available")
        if (!shizukuManager.hasPermission()) throw Exception("Shizuku permission not granted")

        val steps = configManager.bootCommandSequence.split(",").map { it.trim() }

        for (step in steps) {
            when (step) {
                "copy_internal" -> {
                    val sourcePath = configManager.sourcePath
                    val internalPath = configManager.internalStoragePath
                    if (sourcePath.startsWith("assets/")) {
                        val assetName = sourcePath.removePrefix("assets/")
                        context.assets.open(assetName).use { input ->
                            java.io.File(internalPath).also { it.parentFile?.mkdirs() }
                                .outputStream().use { output -> input.copyTo(output) }
                        }
                    }
                }
                "copy_tmp" -> {
                    val src = configManager.internalStoragePath
                    val dst = configManager.targetPath
                    val ok = shizukuManager.copyFile(src, dst)
                    if (ok) shizukuManager.setExecutable(dst)
                    if (!ok) throw Exception("copy_tmp failed")
                }
                "inject" -> {
                    val preset = configManager.getCurrentPreset()
                    val result = shizukuManager.executeWithLDPreload(
                        configManager.targetPath, preset.command, preset.envVars
                    )
                    if (!result.isSuccess) throw Exception("inject failed: ${result.stderr}")
                }
            }
        }
    }

    private fun createNotificationChannel(manager: NotificationManager) {
        val channel = NotificationChannel(
            CHANNEL_ID, "开机自启动", NotificationManager.IMPORTANCE_DEFAULT
        )
        manager.createNotificationChannel(channel)
    }

    companion object {
        private const val CHANNEL_ID = "boot_auto_run_channel"
        private const val NOTIFICATION_ID = 1001
    }
}
