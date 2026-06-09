"""
Generate a C header file from profile.json for embedded agent configuration.
This header is compiled directly into the beacon binary.

Usage:
    python generate_build_config.py <profile.json> <output_header.h>
"""

import json
import sys
import os

if len(sys.argv) != 3:
    sys.stderr.write("Usage: python generate_build_config.py <profile.json> <output_header.h>\n")
    sys.exit(1)

profile_path = sys.argv[1]
output_path = sys.argv[2]

if not os.path.exists(profile_path):
    sys.stderr.write(f"Profile file not found: {profile_path}\n")
    sys.exit(1)

with open(profile_path, "r", encoding="utf-8") as f:
    data = json.load(f)

profile = data.get("profile", {})
connection = profile.get("connection", {})
http = profile.get("http", {})
sleep = profile.get("sleep", {})

server_ip = connection.get("server_ip", "127.0.0.1")
server_port = connection.get("server_port", 8080)
user_agent = http.get("user_agent", "Mozilla/5.0")
auth_token = connection.get("auth_token", "")
sleep_base = sleep.get("base_ms", 5000)
sleep_jitter = sleep.get("jitter_ms", 3000)
use_https = 1 if connection.get("use_https", False) else 0

# Escape backslashes and quotes for C string literals
def escape_c_string(s):
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    return s

user_agent = escape_c_string(user_agent)
auth_token = escape_c_string(auth_token)
server_ip = escape_c_string(server_ip)

# Generate C header file
header_content = f"""#ifndef AGENT_CONFIG_H
#define AGENT_CONFIG_H

// Auto-generated agent configuration from profile.json
// DO NOT EDIT - regenerate with: python generate_build_config.py <profile.json> <output.h>

#define C2_SERVER_IP "{server_ip}"
#define C2_SERVER_PORT {server_port}
#define C2_USER_AGENT "{user_agent}"
#define C2_AUTH_TOKEN "{auth_token}"
#define C2_SLEEP_BASE_MS {sleep_base}
#define C2_SLEEP_JITTER_MS {sleep_jitter}
#define C2_USE_HTTPS {use_https}

#endif // AGENT_CONFIG_H
"""

with open(output_path, "w", encoding="utf-8") as f:
    f.write(header_content)

print(f"Generated: {output_path}")
