import logging, time
import logging.handlers as handlers

logger = logging.getLogger('test')
logger.setLevel(logging.WARN)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh = logging.FileHandler('test.log')
fh.setLevel(logging.WARN)
fh.setFormatter(formatter)
logger.addHandler(fh)

def main():
    logger.warn("Testing log lib")

main()