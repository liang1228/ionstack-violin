package com.violin.injector

import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.violin.injector.databinding.ActivitySettingsBinding

class SettingsActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySettingsBinding
    private lateinit var configManager: ConfigManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)

        configManager = ConfigManager.getInstance(this)

        binding.settingsContent.text = buildString {
            appendLine("=== Violin Root 设置 ===")
            appendLine()
            appendLine("源文件路径: ${configManager.sourcePath}")
            appendLine("内部存储路径: ${configManager.internalStoragePath}")
            appendLine("目标路径: ${configManager.targetPath}")
            appendLine("目标包名: ${configManager.targetPackage.ifEmpty { "(默认)" }}")
            appendLine("当前预设: ${configManager.getCurrentPreset().name}")
            appendLine("MD5 校验: ${if (configManager.enableMd5Check) "开启" else "关闭"}")
            appendLine("开机自启: ${if (configManager.bootAutoRun) "开启" else "关闭"}")
            appendLine("自启序列: ${configManager.bootCommandSequence}")
            appendLine()
            appendLine("=== 可用预设 ===")
            configManager.getCommandPresets().forEachIndexed { i, preset ->
                val marker = if (i == configManager.selectedPresetIndex) "▶ " else "  "
                appendLine("$marker[$i] ${preset.name}: ${preset.command}")
            }
            appendLine()
            appendLine("=== 配置管理 ===")
            appendLine("配置内容 (JSON):")
            appendLine(configManager.exportConfig())
        }
    }
}
