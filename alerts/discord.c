#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "discord.h"
#include "../security/lockout.h"

#define WEBHOOK_URL "https://discord.com/api/webhooks/1501005862074978495/x0VHqX46slzN-pUaey49zTaaX3AHpAyB7h-bEjzdn8UxBq_LJrTbhOndiQkGcYW1Y3qU"
#define ALERT_JSON_PATH "C:\\msys64\\tmp\\discord_alert.json"
#define ALERT_CURL_CONFIG_PATH "C:\\msys64\\tmp\\discord_alert.curl"

static const char *get_webhook_url(void) {
    const char *env = getenv("DISCORD_WEBHOOK_URL");
    if (env != NULL && *env != '\0') {
        return env;
    }
    return WEBHOOK_URL;
}

static int discord_send_content(const char *content) {
    FILE *json = fopen(ALERT_JSON_PATH, "w");
    if (!json) {
        return 0;
    }

    fprintf(json, "{\"content\": \"%s\"}", content);
    fclose(json);

    FILE *curl_config = fopen(ALERT_CURL_CONFIG_PATH, "w");
    if (!curl_config) {
        return 0;
    }

    fprintf(curl_config, "silent\n");
    fprintf(curl_config, "header = \"Content-Type: application/json\"\n");
    fprintf(curl_config, "data-binary = \"@C:/msys64/tmp/discord_alert.json\"\n");
    fprintf(curl_config, "url = \"%s\"\n", get_webhook_url());
    fclose(curl_config);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "C:\\msys64\\usr\\bin\\curl.exe --config C:/msys64/tmp/discord_alert.curl");

#ifdef _WIN32
    FILE *pipe = _popen(cmd, "r");
#else
    FILE *pipe = popen(cmd, "r");
#endif
    if (!pipe) {
        return 0;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
    }

    int ret;
#ifdef _WIN32
    ret = _pclose(pipe);
#else
    ret = pclose(pipe);
#endif

    return (ret == 0) ? 1 : 0;
}

int discord_alert(const char *title, const char *filepath, int attempts) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    if (!t) {
        return 0;
    }

    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    char hostname[64] = "Unknown";
#ifdef _WIN32
    char *env = getenv("COMPUTERNAME");
    if (env != NULL && *env != '\0') {
        strncpy(hostname, env, sizeof(hostname) - 1);
        hostname[sizeof(hostname) - 1] = '\0';
    }
#endif

    const char *safe_title = (title != NULL) ? title : "Unknown";
    const char *safe_path = (filepath != NULL) ? filepath : "Unknown";

    char escaped_title[256];
    char escaped_path[1024];
    strncpy(escaped_title, safe_title, sizeof(escaped_title) - 1);
    escaped_title[sizeof(escaped_title) - 1] = '\0';
    strncpy(escaped_path, safe_path, sizeof(escaped_path) - 1);
    escaped_path[sizeof(escaped_path) - 1] = '\0';

    for (char *p = escaped_title; *p; ++p) {
        if (*p == '"') *p = '\'';
    }
    for (char *p = escaped_path; *p; ++p) {
        if (*p == '"') *p = '\'';
    }

    char content[1536];
    snprintf(content, sizeof(content),
             "\\ud83d\\udea8 %s\\n"
             "\\ud83d\\udcc1 File: %s\\n"
             "\\u23f0 Time: %s\\n"
             "\\u274c Attempts: %d/5\\n"
             "\\ud83d\\udcbb Machine: %s\\n"
             "\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500",
             escaped_title, escaped_path, timestamp, attempts, hostname);

    return discord_send_content(content);
}

int discord_duress_password_alert(const char *filepath) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    if (!t) {
        return 0;
    }

    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    char hostname[64] = "Unknown";
#ifdef _WIN32
    char *env = getenv("COMPUTERNAME");
    if (env != NULL && *env != '\0') {
        strncpy(hostname, env, sizeof(hostname) - 1);
        hostname[sizeof(hostname) - 1] = '\0';
    }
#endif

    const char *safe_path = (filepath != NULL) ? filepath : "Unknown";
    char escaped_path[1024];
    strncpy(escaped_path, safe_path, sizeof(escaped_path) - 1);
    escaped_path[sizeof(escaped_path) - 1] = '\0';
    for (char *p = escaped_path; *p; ++p) {
        if (*p == '"') *p = '\'';
    }

    char content[1536];
    snprintf(content, sizeof(content),
             "\\u26a0\\ufe0f DURESS PASSWORD USED!\\n"
             "\\ud83d\\udcc1 File     : %s\\n"
             "\\u23f0 Time     : %s\\n"
             "\\ud83d\\udea8 Someone may be under coercion!\\n"
             "\\ud83d\\udcbb Machine  : %s\\n"
             "\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500",
             escaped_path, timestamp, hostname);

    return discord_send_content(content);
}

int discord_vault_locked_alert(const char *filepath) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    if (!t) {
        return 0;
    }

    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    char hostname[64] = "Unknown";
#ifdef _WIN32
    char *env = getenv("COMPUTERNAME");
    if (env != NULL && *env != '\0') {
        strncpy(hostname, env, sizeof(hostname) - 1);
        hostname[sizeof(hostname) - 1] = '\0';
    }
#endif

    const char *safe_path = (filepath != NULL) ? filepath : "Unknown";
    char escaped_path[1024];
    strncpy(escaped_path, safe_path, sizeof(escaped_path) - 1);
    escaped_path[sizeof(escaped_path) - 1] = '\0';
    for (char *p = escaped_path; *p; ++p) {
        if (*p == '"') *p = '\'';
    }

    char content[1536];
    snprintf(content, sizeof(content),
             "\\ud83d\\udd12 VAULT LOCKED!\\n"
             "\\ud83d\\udcc1 File     : %s\\n"
             "\\u23f0 Time     : %s\\n"
             "\\u274c Attempts : %d/5 \\u2014 LOCKED\\n"
             "\\ud83d\\udcbb Machine  : %s\\n"
             "\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500\\u2500",
             escaped_path, timestamp, MAX_ATTEMPTS, hostname);

    return discord_send_content(content);
}
