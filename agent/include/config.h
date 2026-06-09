#ifndef CONFIG_H
#define CONFIG_H

// Compile-time beacon configuration.
// Override these values with -D flags in build.bat or by editing this file.

#ifndef C2_SERVER_IP
#define C2_SERVER_IP "127.0.0.1"
#endif

#ifndef C2_SERVER_PORT
#define C2_SERVER_PORT 8080
#endif

#ifndef C2_USER_AGENT
#define C2_USER_AGENT "Mozilla/5.0"
#endif

#ifndef C2_SLEEP_BASE_MS
#define C2_SLEEP_BASE_MS 5000
#endif

#ifndef C2_SLEEP_JITTER_MS
#define C2_SLEEP_JITTER_MS 3000
#endif

#ifndef C2_AUTH_TOKEN
#define C2_AUTH_TOKEN ""
#endif

#endif // CONFIG_H
