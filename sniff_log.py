import logging, time
import logging.handlers as handlers

def log_to_file(path,payload,name):
    logger = logging.getLogger(name)
    logger.setLevel(logging.WARN)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(message)s')
    fh = logging.FileHandler(path)
    fh.setLevel(logging.WARN)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.warn(payload)
