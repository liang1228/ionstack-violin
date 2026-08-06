package com.violin.injector

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.text.format.DateFormat
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.violin.injector.databinding.ActivityMainBinding
import kotlinx.coroutines.*
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var configManager: ConfigManager
    private lateinit var shizukuManager: ShizukuManager
    private val scope = CoroutineScope(Dispatchers.Main)
    private val logLines = mutableListOf<String>()

    companion object {
        private const val REQUEST_STORAGE_PERMISSION = 2001
        private const val LOG_DIR_NAME = "ViolinRoot"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        configManager = ConfigManager.getInstance(this)
        shizukuManager = ShizukuManager(this)

        setupListeners()
        requestStoragePermissionIfNeeded()
        updateStatus()
        collectCrashLogs()
    }

    // ========== Storage Permission ==========

    private fun requestStoragePermissionIfNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                AlertDialog.Builder(this)
                    .setTitle("需要存储权限")
                    .setMessage("Violin Root 需要「所有文件访问」权限来：\n\n" +
                            "• 复制 preload.so 到内部存储\n" +
                            "• 保存运行日志和崩溃日志\n" +
                            "• 读取设备上的 exploit 文件\n\n" +
                            "请点击「授权」前往设置开启。")
                    .setPositiveButton("授权") { _, _ ->
                        try {
                            val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                            intent.data = Uri.parse("package:$packageName")
                            startActivity(intent)
                        } catch (e: Exception) {
                            val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                            startActivity(intent)
                        }
                    }
                    .setNegativeButton("稍后", null)
                    .show()
            }
        } else {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this,
                    arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE,
                        Manifest.permission.WRITE_EXTERNAL_STORAGE),
                    REQUEST_STORAGE_PERMISSION)
            }
        }
    }

    // ========== Listeners ==========

    private fun setupListeners() {
        binding.btnCopyInternal.setOnClickListener { copyToInternalStorage() }
        binding.btnPermission.setOnClickListener { requestShizukuPermission() }
        binding.btnCopyTmp.setOnClickListener { copyToTmp() }
        binding.btnInject.setOnClickListener { executeInjection() }
        binding.btnOneClick.setOnClickListener { oneClickExecute() }
        binding.btnSettings.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        // Log buttons
        binding.btnCopyLog.setOnClickListener { copyLogToClipboard() }
        binding.btnSaveLog.setOnClickListener { saveLogToFile() }
        binding.btnCollectCrash.setOnClickListener { collectCrashLogs() }
    }

    // ========== Status ==========

    private fun updateStatus() {
        val shizukuAvailable = shizukuManager.isServiceAvailable()
        val hasPermission = shizukuManager.hasPermission()

        if (!shizukuAvailable) {
            binding.statusShizuku.text = getString(R.string.status_shizuku_unavailable)
            binding.statusShizuku.setTextColor(ContextCompat.getColor(this, R.color.color_error))
        } else if (!hasPermission) {
            binding.statusShizuku.text = getString(R.string.status_shizuku_no_permission)
            binding.statusShizuku.setTextColor(ContextCompat.getColor(this, R.color.color_warning))
        } else {
            binding.statusShizuku.text = getString(R.string.status_shizuku_ready)
            binding.statusShizuku.setTextColor(ContextCompat.getColor(this, R.color.color_success))
        }

        // Storage permission status
        val hasStorage = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) ==
                    PackageManager.PERMISSION_GRANTED
        }
        binding.statusStorage.text = if (hasStorage) "✅ 存储权限已授予" else "⚠️ 存储权限未授予"
        binding.statusStorage.setTextColor(
            ContextCompat.getColor(this, if (hasStorage) R.color.color_success else R.color.color_warning)
        )

        val internalPath = configManager.internalStoragePath
        val internalExists = File(internalPath).exists()
        binding.statusFileInternal.text = if (internalExists) {
            getString(R.string.status_file_exists, internalPath)
        } else {
            getString(R.string.status_file_missing, internalPath)
        }
        binding.statusFileInternal.setTextColor(
            ContextCompat.getColor(this, if (internalExists) R.color.color_success else R.color.color_warning)
        )

        if (hasPermission) {
            scope.launch(Dispatchers.IO) {
                val tmpPath = configManager.targetPath
                val exists = shizukuManager.fileExists(tmpPath)
                withContext(Dispatchers.Main) {
                    binding.statusFileTmp.text = if (exists) {
                        getString(R.string.status_file_exists, tmpPath)
                    } else {
                        getString(R.string.status_file_missing, tmpPath)
                    }
                    binding.statusFileTmp.setTextColor(
                        ContextCompat.getColor(this@MainActivity, if (exists) R.color.color_success else R.color.color_warning)
                    )
                }
            }
        } else {
            binding.statusFileTmp.text = getString(R.string.status_file_need_permission)
            binding.statusFileTmp.setTextColor(ContextCompat.getColor(this, R.color.color_warning))
        }
    }

    // ========== Log ==========

    private fun appendLog(message: String) {
        runOnUiThread {
            val timestamp = DateFormat.format("HH:mm:ss", System.currentTimeMillis())
            val line = "[$timestamp] $message"
            logLines.add(line)

            val current = binding.logOutput.text.toString()
            binding.logOutput.text = if (current.isNotEmpty()) "$current\n$line" else line

            // Auto-save on important events
            if (message.contains("成功") || message.contains("失败") || message.contains("中止") ||
                message.contains("exit_code") || message.contains("stdout") || message.contains("stderr")) {
                autoSaveLog()
            }
        }
    }

    private fun copyLogToClipboard() {
        val text = logLines.joinToString("\n")
        if (text.isEmpty()) {
            Toast.makeText(this, "日志为空", Toast.LENGTH_SHORT).show()
            return
        }
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("ViolinRoot Log", text))
        Toast.makeText(this, "日志已复制到剪贴板", Toast.LENGTH_SHORT).show()
    }

    private fun getLogDir(): File {
        val dir = File(Environment.getExternalStorageDirectory(), LOG_DIR_NAME)
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    private fun saveLogToFile(): String? {
        if (logLines.isEmpty()) {
            Toast.makeText(this, "日志为空", Toast.LENGTH_SHORT).show()
            return null
        }
        return try {
            val dir = getLogDir()
            val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
            val file = File(dir, "log-$ts.txt")
            file.writeText(logLines.joinToString("\n"))
            Toast.makeText(this, "日志已保存: ${file.absolutePath}", Toast.LENGTH_LONG).show()
            appendLog("日志已保存: ${file.absolutePath}")
            file.absolutePath
        } catch (e: Exception) {
            Toast.makeText(this, "保存失败: ${e.message}", Toast.LENGTH_SHORT).show()
            null
        }
    }

    private fun autoSaveLog() {
        try {
            val dir = getLogDir()
            val file = File(dir, "log-latest.txt")
            file.writeText(logLines.joinToString("\n"))
        } catch (_: Exception) { }
    }

    // ========== Crash Log Collection ==========

    private fun collectCrashLogs() {
        scope.launch(Dispatchers.IO) {
            val collected = StringBuilder()
            collected.appendLine("=== Violin Root Crash Log Collection ===")
            collected.appendLine("Time: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
            collected.appendLine("Device: ${Build.MODEL} (${Build.DEVICE})")
            collected.appendLine("Android: ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT})")
            collected.appendLine("Build: ${Build.DISPLAY}")
            collected.appendLine()

            // 1. Collect crash.txt from exploit
            val crashPaths = listOf(
                "/data/data/org.mozilla.firefox/files/crash.txt",
                "/sdcard/Download/crash.txt"
            )
            for (path in crashPaths) {
                try {
                    val result = shizukuManager.executeCommand("cat '$path' 2>/dev/null")
                    if (result.isSuccess && result.stdout.isNotBlank()) {
                        collected.appendLine("=== $path ===")
                        collected.appendLine(result.stdout)
                        collected.appendLine()
                    }
                } catch (_: Exception) {}
            }

            // 2. Collect kernel log (last 100 lines of dmesg)
            try {
                val result = shizukuManager.executeCommand("dmesg | tail -100 2>/dev/null")
                if (result.isSuccess && result.stdout.isNotBlank()) {
                    collected.appendLine("=== dmesg (last 100 lines) ===")
                    collected.appendLine(result.stdout)
                    collected.appendLine()
                }
            } catch (_: Exception) {}

            // 3. Collect logcat crash/panic
            try {
                val result = shizukuManager.executeCommand("logcat -d -t 200 -s AndroidRuntime:* DEBUG:* kernel:* 2>/dev/null")
                if (result.isSuccess && result.stdout.isNotBlank()) {
                    collected.appendLine("=== logcat crash ===")
                    collected.appendLine(result.stdout)
                    collected.appendLine()
                }
            } catch (_: Exception) {}

            // 4. Collect last_kmsg if available
            try {
                val result = shizukuManager.executeCommand("cat /sys/fs/pstore/console-ramoops-0 2>/dev/null || cat /proc/last_kmsg 2>/dev/null | tail -200")
                if (result.isSuccess && result.stdout.isNotBlank()) {
                    collected.appendLine("=== last_kmsg / pstore ===")
                    collected.appendLine(result.stdout)
                    collected.appendLine()
                }
            } catch (_: Exception) {}

            // 5. Collect uptime and boot reason
            try {
                val uptime = shizukuManager.executeCommand("uptime 2>/dev/null")
                val bootReason = shizukuManager.executeCommand("cat /proc/bootinfo/boot_reason 2>/dev/null || getprop ro.boot.bootreason 2>/dev/null")
                collected.appendLine("=== Boot Info ===")
                collected.appendLine("uptime: ${uptime.stdout.trim()}")
                collected.appendLine("boot_reason: ${bootReason.stdout.trim()}")
                collected.appendLine()
            } catch (_: Exception) {}

            // Save crash log
            val content = collected.toString()
            withContext(Dispatchers.Main) {
                try {
                    val dir = getLogDir()
                    val ts = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
                    val file = File(dir, "crash-$ts.txt")
                    file.writeText(content)
                    appendLog("崩溃日志已收集: ${file.absolutePath}")

                    // Also keep a latest copy
                    File(dir, "crash-latest.txt").writeText(content)
                } catch (e: Exception) {
                    appendLog("崩溃日志收集失败: ${e.message}")
                }
            }
        }
    }

    // ========== Step Operations ==========

    private fun copyToInternalStorage() {
        appendLog(getString(R.string.log_start_copy_internal))
        scope.launch(Dispatchers.IO) {
            try {
                val sourcePath = configManager.sourcePath
                val internalPath = configManager.internalStoragePath

                if (sourcePath.startsWith("assets/")) {
                    val assetName = sourcePath.removePrefix("assets/")
                    assets.open(assetName).use { input ->
                        File(internalPath).also { it.parentFile?.mkdirs() }
                            .outputStream().use { output -> input.copyTo(output) }
                    }
                } else {
                    val srcFile = File(sourcePath)
                    if (!srcFile.exists()) throw Exception("Source file not found: $sourcePath")
                    srcFile.copyTo(File(internalPath), overwrite = true)
                }

                withContext(Dispatchers.Main) {
                    appendLog(getString(R.string.log_copy_internal_success))
                    Toast.makeText(this@MainActivity, R.string.toast_copy_success, Toast.LENGTH_SHORT).show()
                    updateStatus()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    appendLog(getString(R.string.log_copy_internal_failed, e.message))
                    Toast.makeText(this@MainActivity, getString(R.string.toast_copy_failed, e.message), Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun requestShizukuPermission() {
        appendLog(getString(R.string.log_start_request_permission))
        if (!shizukuManager.isServiceAvailable()) {
            appendLog(getString(R.string.log_shizuku_unavailable))
            Toast.makeText(this, R.string.toast_shizuku_unavailable, Toast.LENGTH_LONG).show()
            return
        }
        shizukuManager.requestPermission { granted ->
            if (granted) {
                appendLog(getString(R.string.log_permission_granted))
                Toast.makeText(this, R.string.toast_permission_granted, Toast.LENGTH_SHORT).show()
            } else {
                appendLog(getString(R.string.log_permission_denied))
                Toast.makeText(this, R.string.toast_permission_denied, Toast.LENGTH_SHORT).show()
            }
            updateStatus()
        }
    }

    private fun copyToTmp() {
        if (!shizukuManager.hasPermission()) {
            appendLog(getString(R.string.log_need_permission_first))
            Toast.makeText(this, R.string.toast_need_permission, Toast.LENGTH_SHORT).show()
            return
        }
        appendLog(getString(R.string.log_start_copy_tmp))
        scope.launch(Dispatchers.IO) {
            try {
                val src = configManager.internalStoragePath
                val dst = configManager.targetPath
                val copySuccess = shizukuManager.copyFile(src, dst)
                val chmodSuccess = if (copySuccess) shizukuManager.setExecutable(dst) else false

                if (configManager.enableMd5Check && copySuccess) {
                    val localMd5 = calculateLocalMd5(src)
                    val remoteMd5 = shizukuManager.getFileMd5(dst)
                    if (localMd5.isNotEmpty() && remoteMd5.isNotEmpty() && localMd5 != remoteMd5) {
                        withContext(Dispatchers.Main) {
                            appendLog(getString(R.string.log_md5_mismatch))
                        }
                        return@launch
                    }
                }

                withContext(Dispatchers.Main) {
                    if (copySuccess && chmodSuccess) {
                        appendLog(getString(R.string.log_copy_tmp_success))
                        Toast.makeText(this@MainActivity, R.string.toast_copy_tmp_success, Toast.LENGTH_SHORT).show()
                    } else {
                        appendLog(getString(R.string.log_copy_tmp_failed))
                        Toast.makeText(this@MainActivity, R.string.toast_copy_tmp_failed, Toast.LENGTH_SHORT).show()
                    }
                    updateStatus()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    appendLog(getString(R.string.log_copy_tmp_failed))
                    Toast.makeText(this@MainActivity, R.string.toast_copy_tmp_failed, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private fun executeInjection() {
        if (!shizukuManager.hasPermission()) {
            appendLog(getString(R.string.log_need_permission_first))
            Toast.makeText(this, R.string.toast_need_permission, Toast.LENGTH_SHORT).show()
            return
        }
        appendLog(getString(R.string.log_start_inject))
        scope.launch(Dispatchers.IO) {
            val targetPath = configManager.targetPath
            val preset = configManager.getCurrentPreset()
            // Use LD_LIBRARY_PATH to fix linker namespace issue on Android 16
            val envVars = preset.envVars.toMutableMap()
            envVars["LD_LIBRARY_PATH"] = "/data/local/tmp"
            val command = preset.command
            val result = shizukuManager.executeWithLDPreload(targetPath, command, envVars)

            withContext(Dispatchers.Main) {
                appendLog(getString(R.string.log_inject_exit_code, result.exitCode))
                if (result.stdout.isNotBlank()) {
                    appendLog(getString(R.string.log_stdout, result.stdout.trim()))
                }
                if (result.stderr.isNotBlank()) {
                    appendLog(getString(R.string.log_stderr, result.stderr.trim()))
                }
                if (result.isSuccess) {
                    Toast.makeText(this@MainActivity, R.string.toast_inject_success, Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this@MainActivity, R.string.toast_inject_failed, Toast.LENGTH_SHORT).show()
                }
                // Collect crash logs after injection
                collectCrashLogs()
            }
        }
    }

    private fun oneClickExecute() {
        appendLog(getString(R.string.log_start_one_click))
        scope.launch(Dispatchers.IO) {
            try {
                // Step 1: Copy to internal storage
                withContext(Dispatchers.Main) { appendLog(getString(R.string.log_step_copy_internal)) }
                val sourcePath = configManager.sourcePath
                val internalPath = configManager.internalStoragePath
                if (sourcePath.startsWith("assets/")) {
                    val assetName = sourcePath.removePrefix("assets/")
                    assets.open(assetName).use { input ->
                        File(internalPath).also { it.parentFile?.mkdirs() }
                            .outputStream().use { output -> input.copyTo(output) }
                    }
                }

                // Step 2: Request Shizuku permission
                withContext(Dispatchers.Main) { appendLog(getString(R.string.log_step_permission)) }
                if (!shizukuManager.hasPermission()) {
                    val granted = withContext(Dispatchers.Main) {
                        suspendCancellableCoroutine<Boolean> { cont ->
                            shizukuManager.requestPermission { cont.resumeWith(Result.success(it)) }
                        }
                    }
                    if (!granted) {
                        withContext(Dispatchers.Main) {
                            appendLog(getString(R.string.log_step_failed, "Permission not granted"))
                            appendLog(getString(R.string.log_one_click_aborted))
                        }
                        return@launch
                    }
                }

                // Step 3: Copy to /data/local/tmp
                withContext(Dispatchers.Main) { appendLog(getString(R.string.log_step_copy_tmp)) }
                val copyOk = shizukuManager.copyFile(configManager.internalStoragePath, configManager.targetPath)
                if (!copyOk) {
                    withContext(Dispatchers.Main) {
                        appendLog(getString(R.string.log_step_failed, "Copy failed"))
                        appendLog(getString(R.string.log_one_click_aborted))
                    }
                    return@launch
                }
                shizukuManager.setExecutable(configManager.targetPath)
                withContext(Dispatchers.Main) { appendLog(getString(R.string.log_step_success)) }

                // Step 4: Execute injection
                withContext(Dispatchers.Main) { appendLog(getString(R.string.log_step_inject)) }
                val preset = configManager.getCurrentPreset()
                val envVars = preset.envVars.toMutableMap()
                envVars["LD_LIBRARY_PATH"] = "/data/local/tmp"
                val result = shizukuManager.executeWithLDPreload(
                    configManager.targetPath, preset.command, envVars
                )

                withContext(Dispatchers.Main) {
                    if (result.isSuccess) {
                        appendLog(getString(R.string.log_one_click_success))
                        appendLog(getString(R.string.log_stdout, result.stdout.trim()))
                        Toast.makeText(this@MainActivity, R.string.toast_one_click_success, Toast.LENGTH_SHORT).show()
                    } else {
                        appendLog(getString(R.string.log_one_click_failed))
                        if (result.stderr.isNotBlank()) {
                            appendLog(getString(R.string.log_stderr, result.stderr.trim()))
                        }
                        Toast.makeText(this@MainActivity, R.string.toast_one_click_failed, Toast.LENGTH_SHORT).show()
                    }
                    updateStatus()
                    collectCrashLogs()
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    appendLog(getString(R.string.log_step_failed, e.message))
                    appendLog(getString(R.string.log_one_click_aborted))
                }
            }
        }
    }

    private fun calculateLocalMd5(path: String): String {
        return try {
            val file = File(path)
            if (!file.exists()) return ""
            val md = MessageDigest.getInstance("MD5")
            val buffer = ByteArray(8192)
            FileInputStream(file).use { fis ->
                var bytesRead: Int
                while (fis.read(buffer).also { bytesRead = it } > 0) {
                    md.update(buffer, 0, bytesRead)
                }
            }
            md.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    override fun onResume() {
        super.onResume()
        updateStatus()
    }

    override fun onDestroy() {
        super.onDestroy()
        autoSaveLog()
        shizukuManager.destroy()
    }
}
