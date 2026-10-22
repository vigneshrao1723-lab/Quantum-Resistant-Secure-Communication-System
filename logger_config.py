"""
Central Logging Configuration
"""

import logging
import os
import sys
from pathlib import Path


def setup_logger(logger_name, log_file):
    """
    Create and return a configured logger.
    """

    if getattr(sys, "frozen", False):
        # A packaged app may live somewhere that is not writable (for
        # example Program Files), so its logs go to per-user app data.
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        log_directory = (
            Path(base) / "QuantumResistantSecureComms" / "logs"
            if base
            else Path.home() / ".qrscs" / "logs"
        )
    else:
        # Get the project root (where logger_config.py is located)
        project_root = Path(__file__).resolve().parent

        # Create logs directory inside the project root
        log_directory = project_root / "logs"
    log_directory.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    # Prevent duplicate handlers if imported multiple times
    if logger.handlers:
        return logger

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        "%Y-%m-%d %H:%M:%S"
    )

    file_handler = logging.FileHandler(
        log_directory / log_file,
        encoding="utf-8"
    )

    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger