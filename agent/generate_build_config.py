import json
import sys
import os

if len(sys.argv) != 2:
    sys.stderr.write("Usage: python generate_build_config.py <profile.json>\n")
    sys.exit(1)

profile_path = sys.argv[1]
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

# Escape any embedded double quotes for CMD compatibility.
user_agent = user_agent.replace('"', "'")
auth_token = auth_token.replace('"', "'")

print(f'set "C2_SERVER_IP={server_ip}"')
print(f'set "C2_SERVER_PORT={server_port}"')
print(f'set "C2_USER_AGENT={user_agent}"')
print(f'set "C2_AUTH_TOKEN={auth_token}"')
print(f'set "C2_SLEEP_BASE_MS={sleep_base}"')
print(f'set "C2_SLEEP_JITTER_MS={sleep_jitter}"')
print(f'set "C2_USE_HTTPS={use_https}"')
