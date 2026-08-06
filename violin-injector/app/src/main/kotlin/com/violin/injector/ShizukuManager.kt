package com.violin.injector

import android.content.Context
import android.os.Handler
import android.os.Looper
import rikka.shizuku.Shizuku
import java.io.BufferedReader
import java.io.InputStreamReader

class ShizukuManager(private val context: Context) {

    private val handler = Handler(Looper.getMainLooper())
    private var onPermissionResultListener: ((Boolean) -> Unit)? = null

    data class CommandResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String
    ) {
        val isSuccess: Boolean get() = exitCode == 0
    }

    fun isServiceAvailable(): Boolean = try {
        Shizuku.pingBinder()
    } catch (e: Exception) {
        false
    }

    fun hasPermission(): Boolean = try {
        Shizuku.checkSelfPermission() == 0
    } catch (e: Exception) {
        false
    }

    fun requestPermission(callback: (Boolean) -> Unit) {
        onPermissionResultListener = callback
        if (hasPermission()) {
            callback(true)
            return
        }
        val listener = object : Shizuku.OnRequestPermissionResultListener {
            override fun onRequestPermissionResult(requestCode: Int, grantResult: Int) {
                Shizuku.removeRequestPermissionResultListener(this)
                val granted = grantResult == 0
                onPermissionResultListener?.invoke(granted)
                onPermissionResultListener = null
            }
        }
        Shizuku.addRequestPermissionResultListener(listener)
        Shizuku.requestPermission(REQUEST_CODE_PERMISSION)
    }

    fun executeCommand(command: String, envVars: Map<String, String> = emptyMap()): CommandResult {
        return try {
            val envArray = if (envVars.isNotEmpty()) {
                envVars.map { "${it.key}=${it.value}" }.toTypedArray()
            } else {
                null
            }
            // Use reflection to call Shizuku.newProcess() which may be hidden/private
            val method = Shizuku::class.java.getDeclaredMethod(
                "newProcess",
                Array<String>::class.java,
                Array<String>::class.java,
                String::class.java
            )
            method.isAccessible = true
            val process = method.invoke(null, arrayOf("sh", "-c", command), envArray, null) as Process
            val stdout = BufferedReader(InputStreamReader(process.inputStream)).readText()
            val stderr = BufferedReader(InputStreamReader(process.errorStream)).readText()
            val exitCode = process.waitFor()
            CommandResult(exitCode, stdout, stderr)
        } catch (e: Exception) {
            // Fallback: try via Runtime.exec with su if Shizuku fails
            try {
                val su = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))
                val stdout = BufferedReader(InputStreamReader(su.inputStream)).readText()
                val stderr = BufferedReader(InputStreamReader(su.errorStream)).readText()
                val exitCode = su.waitFor()
                CommandResult(exitCode, stdout, stderr)
            } catch (e2: Exception) {
                CommandResult(-1, "", e.message ?: e2.message ?: "Unknown error")
            }
        }
    }

    fun executeWithLDPreload(
        preloadPath: String,
        targetCommand: String,
        extraEnv: Map<String, String> = emptyMap()
    ): CommandResult {
        val env = mutableMapOf("LD_PRELOAD" to preloadPath)
        env.putAll(extraEnv)
        return executeCommand(targetCommand, env)
    }

    fun copyFile(src: String, dst: String): Boolean {
        val result = executeCommand("cp \"$src\" \"$dst\"")
        return result.exitCode == 0
    }

    fun fileExists(path: String): Boolean {
        val result = executeCommand("test -f \"$path\" && echo exists || echo missing")
        return result.stdout.trim() == "exists"
    }

    fun getFileMd5(path: String): String {
        val result = executeCommand("md5sum \"$path\"")
        return if (result.isSuccess && result.stdout.isNotBlank()) {
            result.stdout.trim().split(" ")[0]
        } else {
            ""
        }
    }

    fun setExecutable(path: String): Boolean {
        val result = executeCommand("chmod 755 \"$path\"")
        return result.exitCode == 0
    }

    fun destroy() {
        onPermissionResultListener = null
    }

    companion object {
        private const val REQUEST_CODE_PERMISSION = 1001
    }
}
