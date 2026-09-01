"""Configuration and API key management for VulNova.

Stores API keys and settings in ~/.vulnova/ directory.
"""

import json
import os
from pathlib import Path
from typing import Optional

_DOTENV_LOADED = False


def _parse_env_file(path: Path) -> None:
    """Load KEY=VALUE lines from a .env file into os.environ (no override)."""
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        val = val.strip().strip('"').strip("'")
        # Don't override variables already set in the real environment.
        if key and key not in os.environ:
            os.environ[key] = val


def _load_dotenv_once() -> None:
    """Best-effort load of a .env file, once per process.

    Search order: $VULNOVA_ENV_FILE, then ./.env, then the repo root .env.
    Safe no-op when no file exists (e.g. in containers using real env vars).
    """
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return
    _DOTENV_LOADED = True

    candidates = []
    override = os.environ.get("VULNOVA_ENV_FILE")
    if override:
        candidates.append(Path(override))
    candidates.append(Path.cwd() / ".env")
    candidates.append(Path(__file__).resolve().parents[2] / ".env")
    for path in candidates:
        try:
            if path and path.is_file():
                _parse_env_file(path)
                return
        except OSError:
            continue


class Config:
    """Manages VulNova configuration and API key storage."""

    APP_DIR_NAME = ".vulnova"
    CONFIG_FILE = "config.json"
    KEYS_FILE = "keys.json"
    CACHE_DB = "cache.db"

    def __init__(self):
        _load_dotenv_once()
        self.app_dir = Path.home() / self.APP_DIR_NAME
        self.app_dir.mkdir(parents=True, exist_ok=True)
        self._config_path = self.app_dir / self.CONFIG_FILE
        self._keys_path = self.app_dir / self.KEYS_FILE
        self._config = self._load_config()
        self._keys = self._load_keys()

    # ─── API Keys ─────────────────────────────────────────────────────────

    def set_api_key(self, name: str, value: str) -> None:
        """Store an API key securely in ~/.vulnova/keys.json."""
        self._keys[name] = value
        self._save_keys()

    def get_api_key(self, name: str) -> Optional[str]:
        """Retrieve an API key. Falls back to environment variables.

        Priority:
        1. keys.json file
        2. Environment variable (VULNOVA_NVD_KEY, VULNOVA_GITHUB_TOKEN)
        """
        # Check stored keys first
        if name in self._keys and self._keys[name]:
            return self._keys[name]

        # Fall back to environment variables (multiple accepted names each).
        env_map = {
            "nvd": ["VULNOVA_NVD_KEY", "NVD_API_KEY"],
            "github": ["VULNOVA_GITHUB_TOKEN", "GITHUB_TOKEN"],
            "cvefeed": ["VULNOVA_CVEFEED_KEY", "CVEFEED_API_KEY"],
        }
        for env_var in env_map.get(name, []):
            value = os.environ.get(env_var)
            if value:
                return value

        return None

    def has_api_key(self, name: str) -> bool:
        """Check if an API key is configured (file or env)."""
        return self.get_api_key(name) is not None

    def list_keys(self) -> dict[str, bool]:
        """Return a dict of key_name -> is_configured for all known keys."""
        known_keys = ["nvd", "github", "cvefeed"]
        return {k: self.has_api_key(k) for k in known_keys}

    # ─── General Config ───────────────────────────────────────────────────

    def get(self, key: str, default=None):
        """Get a configuration value."""
        return self._config.get(key, default)

    def set(self, key: str, value) -> None:
        """Set a configuration value."""
        self._config[key] = value
        self._save_config()

    @property
    def cache_db_path(self) -> Path:
        """Path to the SQLite cache database."""
        return self.app_dir / self.CACHE_DB

    @property
    def cache_ttl(self) -> int:
        """Cache TTL in seconds (default: 24 hours)."""
        return self._config.get("cache_ttl", 86400)

    @cache_ttl.setter
    def cache_ttl(self, seconds: int) -> None:
        self.set("cache_ttl", seconds)

    @property
    def llm_model(self) -> str:
        """Local LLM model name for briefings (default: mistral)."""
        return self._config.get("llm_model", "mistral")

    @llm_model.setter
    def llm_model(self, model: str) -> None:
        self.set("llm_model", model)

    @property
    def llm_endpoint(self) -> str:
        """Local LLM API endpoint (default: ollama localhost)."""
        return self._config.get("llm_endpoint", "http://localhost:11434")

    @llm_endpoint.setter
    def llm_endpoint(self, endpoint: str) -> None:
        self.set("llm_endpoint", endpoint)

    # ─── Paths ────────────────────────────────────────────────────────────

    @property
    def exploitdb_csv_path(self) -> Path:
        """Path to the ExploitDB CSV file."""
        return self.app_dir / "exploitdb" / "files_exploits.csv"

    @property
    def exploitdb_dir(self) -> Path:
        """Directory for ExploitDB data."""
        path = self.app_dir / "exploitdb"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def exploitdb_refresh_hours(self) -> int:
        """How often to refresh the ExploitDB CSV (default: 168 h = 7 days)."""
        return self._config.get("exploitdb_refresh_hours", 168)

    @property
    def metasploit_dir(self) -> Path:
        """Directory for the local Metasploit module index."""
        path = self.app_dir / "metasploit"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def metasploit_index_path(self) -> Path:
        """Path to the trimmed CVE→module index JSON."""
        return self.metasploit_dir / "cve_index.json"

    @property
    def metasploit_refresh_hours(self) -> int:
        """How often to refresh the Metasploit index (default: 24 h)."""
        return self._config.get("metasploit_refresh_hours", 24)

    # ─── Internal ─────────────────────────────────────────────────────────

    def _load_config(self) -> dict:
        if self._config_path.exists():
            try:
                return json.loads(self._config_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_config(self) -> None:
        self._config_path.write_text(
            json.dumps(self._config, indent=2), encoding="utf-8"
        )

    def _load_keys(self) -> dict:
        if self._keys_path.exists():
            try:
                return json.loads(self._keys_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_keys(self) -> None:
        # Set restrictive permissions on keys file
        self._keys_path.write_text(
            json.dumps(self._keys, indent=2), encoding="utf-8"
        )
        try:
            os.chmod(self._keys_path, 0o600)
        except OSError:
            pass  # Windows may not support chmod the same way
