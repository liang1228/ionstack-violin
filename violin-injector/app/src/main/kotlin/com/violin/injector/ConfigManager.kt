package com.violin.injector

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject

class ConfigManager private constructor(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var sourcePath: String
        get() = prefs.getString(KEY_SOURCE_PATH, DEFAULT_SOURCE_PATH) ?: DEFAULT_SOURCE_PATH
        set(value) = prefs.edit().putString(KEY_SOURCE_PATH, value).apply()

    var internalStoragePath: String
        get() = prefs.getString(KEY_INTERNAL_PATH, DEFAULT_INTERNAL_PATH) ?: DEFAULT_INTERNAL_PATH
        set(value) = prefs.edit().putString(KEY_INTERNAL_PATH, value).apply()

    var targetPath: String
        get() = prefs.getString(KEY_TARGET_PATH, DEFAULT_TARGET_PATH) ?: DEFAULT_TARGET_PATH
        set(value) = prefs.edit().putString(KEY_TARGET_PATH, value).apply()

    var selectedPresetIndex: Int
        get() = prefs.getInt(KEY_SELECTED_PRESET_INDEX, 0)
        set(value) = prefs.edit().putInt(KEY_SELECTED_PRESET_INDEX, value).apply()

    var customCommand: String
        get() = prefs.getString(KEY_CUSTOM_COMMAND, "") ?: ""
        set(value) = prefs.edit().putString(KEY_CUSTOM_COMMAND, value).apply()

    var targetPackage: String
        get() = prefs.getString(KEY_TARGET_PACKAGE, "") ?: ""
        set(value) = prefs.edit().putString(KEY_TARGET_PACKAGE, value).apply()

    var enableMd5Check: Boolean
        get() = prefs.getBoolean(KEY_ENABLE_MD5_CHECK, true)
        set(value) = prefs.edit().putBoolean(KEY_ENABLE_MD5_CHECK, value).apply()

    var showLogOutput: Boolean
        get() = prefs.getBoolean(KEY_SHOW_LOG_OUTPUT, true)
        set(value) = prefs.edit().putBoolean(KEY_SHOW_LOG_OUTPUT, value).apply()

    var bootAutoRun: Boolean
        get() = prefs.getBoolean(KEY_BOOT_AUTO_RUN, false)
        set(value) = prefs.edit().putBoolean(KEY_BOOT_AUTO_RUN, value).apply()

    var bootCommandSequence: String
        get() = prefs.getString(KEY_BOOT_COMMAND_SEQUENCE, "copy_tmp,inject") ?: "copy_tmp,inject"
        set(value) = prefs.edit().putString(KEY_BOOT_COMMAND_SEQUENCE, value).apply()

    fun getCommandPresets(): List<CommandPreset> {
        val jsonStr = prefs.getString(KEY_COMMAND_PRESETS, null)
        if (jsonStr.isNullOrEmpty()) return CommandPreset.defaultPresets()
        return try {
            val arr = JSONArray(jsonStr)
            val list = (0 until arr.length()).map {
                CommandPreset.fromJson(arr.getJSONObject(it))
            }
            list.ifEmpty { CommandPreset.defaultPresets() }
        } catch (e: Exception) {
            CommandPreset.defaultPresets()
        }
    }

    fun saveCommandPresets(presets: List<CommandPreset>) {
        val arr = JSONArray()
        presets.forEach { arr.put(it.toJson()) }
        prefs.edit().putString(KEY_COMMAND_PRESETS, arr.toString()).apply()
    }

    fun getCurrentPreset(): CommandPreset {
        val presets = getCommandPresets()
        val index = selectedPresetIndex.coerceIn(0, presets.size - 1)
        return presets[index]
    }

    fun exportConfig(): String {
        val root = JSONObject()
        root.put(KEY_SOURCE_PATH, sourcePath)
        root.put(KEY_INTERNAL_PATH, internalStoragePath)
        root.put(KEY_TARGET_PATH, targetPath)
        root.put(KEY_SELECTED_PRESET_INDEX, selectedPresetIndex)
        root.put(KEY_COMMAND_PRESETS, JSONArray().apply {
            getCommandPresets().forEach { put(it.toJson()) }
        })
        root.put(KEY_CUSTOM_COMMAND, customCommand)
        root.put(KEY_TARGET_PACKAGE, targetPackage)
        root.put(KEY_ENABLE_MD5_CHECK, enableMd5Check)
        root.put(KEY_SHOW_LOG_OUTPUT, showLogOutput)
        root.put(KEY_BOOT_AUTO_RUN, bootAutoRun)
        root.put(KEY_BOOT_COMMAND_SEQUENCE, bootCommandSequence)
        return root.toString(2)
    }

    fun importConfig(jsonStr: String): Boolean {
        return try {
            val root = JSONObject(jsonStr)
            val editor = prefs.edit()
            root.optString(KEY_SOURCE_PATH).takeIf { it.isNotEmpty() }?.let { editor.putString(KEY_SOURCE_PATH, it) }
            root.optString(KEY_INTERNAL_PATH).takeIf { it.isNotEmpty() }?.let { editor.putString(KEY_INTERNAL_PATH, it) }
            root.optString(KEY_TARGET_PATH).takeIf { it.isNotEmpty() }?.let { editor.putString(KEY_TARGET_PATH, it) }
            if (root.has(KEY_SELECTED_PRESET_INDEX)) editor.putInt(KEY_SELECTED_PRESET_INDEX, root.getInt(KEY_SELECTED_PRESET_INDEX))
            root.optJSONArray(KEY_COMMAND_PRESETS)?.let { editor.putString(KEY_COMMAND_PRESETS, it.toString()) }
            root.optString(KEY_CUSTOM_COMMAND).let { editor.putString(KEY_CUSTOM_COMMAND, it) }
            root.optString(KEY_TARGET_PACKAGE).let { editor.putString(KEY_TARGET_PACKAGE, it) }
            if (root.has(KEY_ENABLE_MD5_CHECK)) editor.putBoolean(KEY_ENABLE_MD5_CHECK, root.getBoolean(KEY_ENABLE_MD5_CHECK))
            if (root.has(KEY_SHOW_LOG_OUTPUT)) editor.putBoolean(KEY_SHOW_LOG_OUTPUT, root.getBoolean(KEY_SHOW_LOG_OUTPUT))
            if (root.has(KEY_BOOT_AUTO_RUN)) editor.putBoolean(KEY_BOOT_AUTO_RUN, root.getBoolean(KEY_BOOT_AUTO_RUN))
            root.optString(KEY_BOOT_COMMAND_SEQUENCE).takeIf { it.isNotEmpty() }?.let { editor.putString(KEY_BOOT_COMMAND_SEQUENCE, it) }
            editor.apply()
            true
        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }

    fun resetToDefaults() {
        prefs.edit().clear().apply()
    }

    companion object {
        private const val PREFS_NAME = "violin_injector_config"
        private const val KEY_SOURCE_PATH = "source_path"
        private const val KEY_INTERNAL_PATH = "internal_storage_path"
        private const val KEY_TARGET_PATH = "target_path"
        private const val KEY_SELECTED_PRESET_INDEX = "selected_preset_index"
        private const val KEY_COMMAND_PRESETS = "command_presets"
        private const val KEY_CUSTOM_COMMAND = "custom_command"
        private const val KEY_TARGET_PACKAGE = "target_package"
        private const val KEY_ENABLE_MD5_CHECK = "enable_md5_check"
        private const val KEY_SHOW_LOG_OUTPUT = "show_log_output"
        private const val KEY_BOOT_AUTO_RUN = "boot_auto_run"
        private const val KEY_BOOT_COMMAND_SEQUENCE = "boot_command_sequence"

        const val DEFAULT_SOURCE_PATH = "assets/preload.so"
        const val DEFAULT_INTERNAL_PATH = "/storage/emulated/0/preload.so"
        const val DEFAULT_TARGET_PATH = "/data/local/tmp/preload.so"

        @Volatile
        private var instance: ConfigManager? = null

        fun getInstance(context: Context): ConfigManager {
            return instance ?: synchronized(this) {
                instance ?: ConfigManager(context).also { instance = it }
            }
        }
    }
}
