# Load DB credentials, connect
# to database and return handler
import os
import sys
import imp
import time
from sniffy.utils.cfg_loader import load_db_creds

class DBH:
  def __init__(self, db, creds_file, log):
    # Load creds from file
    self.creds = load_db_creds(creds_file)
    if self.creds.has_key('error'):
      log.error(self.creds['error'])
      exit(1)

    # Seach and load DB module
    lib_path = None
    for dir in sys.path:
      if os.path.isdir(dir + '/sniffy'):
        lib_path = dir
        break
    if not lib_path:
      lib_path = os.path.dirname(os.path.realpath(sys.argv[0])) + '/../lib'
    module_path='%s/sniffy/modules/db/%s.py' % (lib_path, db)
    module_name = 'db_%s' % db
    try:
      self.db = imp.load_source(module_name, module_path)
    except IOError, e:
      sys.stderr.write("ERROR: Cannot load database module '%s' from path '%s': %s\n" \
                     % ( db, module_path, e))
      exit(1)

    self.handler = None

  def connect(self):
    self.handler = self.db.DB(self.creds).connect()
    return self.handler

  def check(self, key, window=60, limit=50):
    # Expire old keys (hits)
    expires = time.time() - window
    self.handler.zremrangebyscore(key, '-inf', expires)

    # Add a hit on the very moment
    now = time.time()
    self.handler.zadd(key, now, now)

    # If we currently have more keys than limit,
    # then limit the action
    if self.handler.zcard(key) > limit:
        return True

    return False

  def get(self, key):
    return self.handler.zcard(key)
