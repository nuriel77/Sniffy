# Logger class
import logging
from os import chmod
from sys import argv

class Log:
  def __init__(self, logfile):
    self.logfile = logfile
    self.logger = None
    self.handler = None

  def set_logger(self):
    logging._defaultFormatter = logging.Formatter(u"%(message)s")
    self.logger = logging.getLogger(argv[0])
    self.logger.setLevel(logging.INFO)
    formatter = logging.Formatter(u"%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    self.handler = logging.FileHandler(self.logfile)
    self.handler.setFormatter(formatter)
    self.logger.addHandler(self.handler)
    self._set_mode()
    return self.logger

  def get_handler(self):
    return self.handler

  def log_to_console(self):
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(u"%(levelname)s - %(message)s"))
    self.logger.addHandler(console_handler)

  def set_debug(self):
    self.logger.setLevel(logging.DEBUG)
    
  def _set_mode(self):
    chmod(self.logfile, 0600)
