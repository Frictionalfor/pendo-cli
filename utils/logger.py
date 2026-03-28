"""
logger.py - Centralized logging system
"""
import logging
import os

LOG_LEVEL = os.environ.get("PENDO_LOG", "ERROR").upper()

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    level=getattr(logging, LOG_LEVEL, logging.WARNING),
)

def get_logger(name):
    return logging.getLogger(name)
