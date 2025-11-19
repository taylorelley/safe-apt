"""Configuration management for safe-apt.

Handles loading and validation of YAML configuration files.
"""

import os
from pathlib import Path
from typing import Any, Dict

import yaml


def load_config(config_path: str = "/opt/apt-mirror-system/config.yaml") -> Dict[str, Any]:
    """Load configuration from YAML file.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        yaml.YAMLError: If config file is invalid YAML
    """
    config_file = Path(config_path)

    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with config_file.open("r") as f:
        config = yaml.safe_load(f)

    # Expand environment variables
    config = _expand_env_vars(config)

    return config


def _expand_env_vars(obj: Any) -> Any:
    """Recursively expand environment variables in configuration.

    Args:
        obj: Configuration object (dict, list, str, etc.)

    Returns:
        Configuration with expanded environment variables
    """
    if isinstance(obj, dict):
        return {key: _expand_env_vars(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [_expand_env_vars(item) for item in obj]
    elif isinstance(obj, str):
        return os.path.expandvars(obj)
    else:
        return obj
