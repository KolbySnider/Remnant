"""
C2 Profile Loader
Handles loading and managing C2 communication profiles (JSON).
Profiles define HTTP headers, paths, encryption, sleep patterns, and connection settings.
"""
import json
import os
from typing import Dict, Any, Optional


class C2Profile:
    def __init__(self, data: Dict[str, Any]):
        self.data = data.get("profile", {})
        self._validate()

    def _validate(self):
        """Ensure required fields are present."""
        required = ["beacon", "http", "encryption", "sleep"]
        for key in required:
            if key not in self.data:
                raise ValueError(f"Profile missing required section: {key}")

    @property
    def name(self) -> str:
        return self.data.get("name", "Unknown Profile")

    @property
    def register_path(self) -> str:
        return self.data["beacon"].get("register_path", "/register")

    @property
    def checkin_path(self) -> str:
        return self.data["beacon"].get("checkin_path", "/checkin")

    @property
    def getbof_path(self) -> str:
        return self.data["beacon"].get("getbof_path", "/getbof")

    @property
    def user_agent(self) -> str:
        return self.data["http"].get("user_agent", "Mozilla/5.0")

    @property
    def auth_header(self) -> str:
        return self.data["http"].get("auth_header", "X-C2-Token")

    @property
    def server_ip(self) -> str:
        return self.data.get("connection", {}).get("server_ip", "127.0.0.1")

    @property
    def server_port(self) -> int:
        return self.data.get("connection", {}).get("server_port", 8080)

    @property
    def use_https(self) -> bool:
        return self.data.get("connection", {}).get("use_https", False)

    @property
    def auth_token(self) -> str:
        return self.data.get("connection", {}).get("auth_token", "")

    @property
    def http_headers(self) -> Dict[str, str]:
        return self.data["http"].get("headers", {})

    @property
    def base_sleep_ms(self) -> int:
        return self.data["sleep"].get("base_ms", 5000)

    @property
    def jitter_ms(self) -> int:
        return self.data["sleep"].get("jitter_ms", 3000)

    def to_dict(self) -> Dict[str, Any]:
        """Return profile as dictionary (for serialization/logging)."""
        return self.data


def load_profile(profile_path: str) -> Optional[C2Profile]:
    """Load a C2 profile from a JSON file.
    
    Args:
        profile_path: Path to the profile JSON file
        
    Returns:
        C2Profile object or None if file doesn't exist
        
    Raises:
        ValueError: If profile is invalid
        json.JSONDecodeError: If JSON is malformed
    """
    if not os.path.exists(profile_path):
        return None

    with open(profile_path, "r") as f:
        data = json.load(f)

    return C2Profile(data)


def load_profile_directory(profile_dir: str) -> Dict[str, C2Profile]:
    """Load all profiles from a directory.
    
    Args:
        profile_dir: Directory containing profile JSON files
        
    Returns:
        Dictionary mapping profile names to C2Profile objects
    """
    profiles = {}
    if not os.path.isdir(profile_dir):
        return profiles

    for filename in os.listdir(profile_dir):
        if filename.endswith(".json"):
            path = os.path.join(profile_dir, filename)
            try:
                profile = load_profile(path)
                if profile:
                    profiles[filename[:-5]] = profile  # Remove .json extension
            except (json.JSONDecodeError, ValueError) as e:
                print(f"[!] Failed to load profile {filename}: {e}")

    return profiles
