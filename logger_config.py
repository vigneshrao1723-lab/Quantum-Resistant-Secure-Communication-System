"""
Central Logging Configuration
"""

import logging
from pathlib import Path


def setup_logger(logger_name, log_file):
    """
    Create and return a configured logger.
    """

    # Get the project root (where logger_config.py is located)
    project_root = Path(__file__).resolve().parent

    # Create logs directory inside the project root
    log_directory = project_root / "logs"
    log_directory.mkdir(exist_ok=True)

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