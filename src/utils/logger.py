import logging
import os
import time
import re
from typing import Optional


def _clean_old_logs(log_dir: str, max_days: int = 90):
    current_time = time.time()
    pattern = re.compile(r'^(\w+)_(\d{8})_\d{6}\.log$')
    
    deleted_count = 0
    for filename in os.listdir(log_dir):
        match = pattern.match(filename)
        if match:
            date_str = match.group(2)
            try:
                file_time = time.mktime(time.strptime(date_str, "%Y%m%d"))
                if current_time - file_time > max_days * 24 * 60 * 60:
                    filepath = os.path.join(log_dir, filename)
                    os.remove(filepath)
                    deleted_count += 1
            except (ValueError, OSError):
                pass
    
    if deleted_count > 0:
        logger = logging.getLogger("Hermit_Y")
        logger.info(f"已清理 {deleted_count} 个超过 {max_days} 天的旧日志文件")


def setup_logging(mode: str = "run", max_log_days: int = 90) -> logging.Logger:
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    _clean_old_logs(log_dir, max_log_days)
    
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    log_filename = f"{mode}_{timestamp}.log"
    log_filepath = os.path.join(log_dir, log_filename)
    
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    if root_logger.handlers:
        root_logger.handlers.clear()
    
    file_handler = logging.FileHandler(log_filepath, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)
    root_logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)
    
    root_logger.info(f"日志系统已初始化，日志文件: {log_filepath}")
    return logging.getLogger("Hermit_Y")


def get_logger(name: str = "Hermit_Y") -> logging.Logger:
    return logging.getLogger(name)