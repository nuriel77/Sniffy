import sys

"""
Try to import redis and show error
 w/ install instructions if it cannot be imported.
"""
try:
  import redis
except ImportError:
  sys.stderr.write("ERROR: You must have redis installed.\n")
  sys.stderr.write("You can install it by running: sudo pip install redis\n")
  exit(1)

class DB:
  def __init__(self, creds):
    self.host = creds['host']
    self.password = creds['password']
    self.port = creds['port']
    self.handler = None

  def connect(self):
    if self.handler == None:
      self.handler = redis.Redis(
        host=self.host,
        port=self.port,
        password=self.password,
        socket_timeout=5)
    return self.handler
