package com.violin.injector

import org.json.JSONObject

data class CommandPreset(
    val name: String,
    val command: String,
    val envVars: Map<String, String> = emptyMap()
) {
    fun toJson(): JSONObject = JSONObject().apply {
        put("name", name)
        put("command", command)
        put("envVars", JSONObject().apply {
            envVars.forEach { (k, v) -> put(k, v) }
        })
    }

    companion object {
        fun fromJson(json: JSONObject): CommandPreset {
            val name = json.getString("name")
            val command = json.getString("command")
            val envVars = mutableMapOf<String, String>()
            json.optJSONObject("envVars")?.let { envJson ->
                envJson.keys().forEach { key ->
                    envVars[key] = envJson.getString(key)
                }
            }
            return CommandPreset(name, command, envVars)
        }

        fun defaultPresets(): List<CommandPreset> = listOf(
            CommandPreset("Violin Root (toybox id)", "/system/bin/toybox id"),
            CommandPreset("Shell 测试", "/system/bin/sh -c id"),
            CommandPreset("系统属性", "/system/bin/getprop")
        )
    }
}
