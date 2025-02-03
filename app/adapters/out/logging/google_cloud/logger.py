import logging
from .handler import GoogleCloudHandler

def get_logger(name):
    logger = logging.getLogger(name)

    logger.handlers.clear()
    if not logger.handlers:
        gcp_handler = GoogleCloudHandler()
        gcp_handler.setLevel(logging.DEBUG)

        #gcp_formatter = logging.Formatter(
        #    '%(levelname)s %(asctime)s [%(filename)s:%(funcName)s:%(lineno)d] %(message)s')
        #gcp_handler.setFormatter(gcp_formatter)
        logger.addHandler(gcp_handler)
    return logger