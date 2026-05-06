import os
import sys
from loguru import logger

LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "logs")
LOG_FILE = os.path.join(LOG_DIR, "iot-server-{time:YYYY-MM-DD}.log")


def init_logging(debug: bool = False) -> None:
    os.makedirs(LOG_DIR, exist_ok=True)

    logger.remove()

    fmt_console = (
        "<green>{time:HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | <level>{message}</level>"
    )
    fmt_file = (
        "{time:YYYY-MM-DD HH:mm:ss.SSS} | {level: <8} | {name}:{function}:{line} | {message}"
    )

    logger.add(
        sys.stdout,
        format=fmt_console,
        level="DEBUG" if debug else "INFO",
        colorize=True,
    )

    logger.add(
        LOG_FILE,
        format=fmt_file,
        level="INFO",
        rotation="1 day",
        retention="30 days",
        compression="gz",
        encoding="utf-8",
    )
