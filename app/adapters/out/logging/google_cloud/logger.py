import logging
from .handler import GoogleCloudHandler
from google.cloud.logging_v2.handlers import setup_logging
import os

def init(): 
    logging.getLogger().handlers.clear()
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    handler = GoogleCloudHandler(project_id=project_id)
    setup_logging(handler)

def get_logger(name):
    return logging.getLogger(name)
