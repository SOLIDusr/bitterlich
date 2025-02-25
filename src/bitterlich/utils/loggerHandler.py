import logging
from datetime import datetime
import os


class SingletonMeta(type):
    _instances: dict[type, object] = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]

class LoggerInstance(metaclass=SingletonMeta):
    def __init__(self, verbose: bool = False):
        console_level = logging.INFO if verbose else logging.ERROR
        logs_dir = "src/bitterlich/logs"
        os.makedirs(logs_dir, exist_ok=True)

        for filename in os.listdir(logs_dir):
            os.remove(os.path.join(logs_dir, filename))

        self._logger = logging.getLogger("Debug")
        self._logger.setLevel(logging.DEBUG)

        fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(fmt)
        console_handler.setLevel(console_level)
        self._logger.addHandler(console_handler)

        timestamp = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")

        debug_handler = logging.FileHandler(f"{logs_dir}/{timestamp}.debug.log")
        debug_handler.setFormatter(fmt)
        debug_handler.setLevel(logging.DEBUG)
        self._logger.addHandler(debug_handler)

        info_handler = logging.FileHandler(f"{logs_dir}/{timestamp}.info.log")
        info_handler.setFormatter(fmt)
        info_handler.setLevel(logging.INFO)
        self._logger.addHandler(info_handler)

    def debug(self, message: str, node: str = "Main") -> None:
        self._logger.debug(f"[{node}] {message}")
    
    def info(self, message: str, node: str = "Main") -> None:
        self._logger.info(f"[{node}] {message}")
    
    def warning(self, message: str, node: str = "Main") -> None:
        self._logger.warning(f"[{node}] {message}")
    
    def error(self, message: str, node: str = "Main") -> None:
        self._logger.error(f"[{node}] {message}")
    
    def critical(self, message: str, node: str = "Main") -> None:
        self._logger.critical(f"[{node}] {message}")
    
    def exception(self, message: str, node: str = "Main") -> None:
        self._logger.exception(f"[{node}] {message}")
