# Check result in database
# whether exceeded rate limit
import time
from sniffy import constants as C
from sniffy.core.iplog import IptablesThread

class CheckDB:
  def __init__(self, log, dbh):
    self.log = log
    self.dbh = dbh
    self.threads = {}

  def check(self, **kwargs):
    """Check data in DB

    Will check if unique signature already exists in
    database. If yes, it will increment the number for
    each time this signature is encountered. If reaches
    a certain limit it will fireup thread to extract
    UID of the offender from dmesg where iptables are
    logged.

    - **params**,**types**

      :param kwargs: Contain all arguments to work with including
                     offending packet data, log handler etc.
      :type kwargs: dict

    - **variables**,**types**

      :var data: Will be used for offending packet data
      :var keysig: Unique key signature to store in DB
      :var uri_result: URI target captured in packet
      :var check: Database result
      :type data: dict
      :type keysig: str
      :type uri_result: str
      :type check: bool

    """

    # Clean up old registered threads
    self._clean_old_threads()

    self.dbh.connect()
    data = kwargs['result']['data']
    uri_result = kwargs['result']['uri_result']

    # Generte key signature
    keysig = '%s_%s_%s:%s' % (C.THIS_HOST,
                              data['dst_ip'],
                              data['method'],
                              uri_result)

    # Check if threshold has been reached
    check = self.dbh.check(keysig,
                           kwargs['window'],
                           kwargs['threshold'])
    if check:
      self.log.info("Hit %s matches threshold for '%s'" % (kwargs['threshold'], keysig))

      # Check that we didn't open the same thread
      # less than 30 seconds ago, or if thread
      # is currently still alive...
      now = int(time.time())
      if self.threads.has_key(keysig):
        if self.threads[keysig]['th'].isAlive() or (now - self.threads[keysig]['time']) < 30:
          self.log.info("Thread for iptables logs for '%s' already opened. Skipping new thread." % keysig)
          return

      self.log.info("Starting up iptables logs search thread for '%s'..." % keysig)
      # Search destination IP in iptables log
      th = IptablesThread(log=self.log,
                          dbh=self.dbh,
                          threshold=kwargs['threshold'],
                          src_ip=data['src_ip'],
                          dst_ip=data['dst_ip'],
                          t=data['time'],
                          path=data['path'],
                          method=data['method'],
                          payload=data['payload'],
                          email=kwargs['email'])
      th.start()
      self.threads[keysig] = {
        'th': th,
        'time': int(time.time())
      }
    else:
      incr = self.dbh.get(keysig)
      self.log.info("Key %s incremented to: %s" % (keysig, incr))

  def _clean_old_threads(self):
    now = int(time.time())
    to_remove = [t for t in self.threads if (now - self.threads[t]['time']) > 30 and not self.threads[t]['th'].isAlive()]
    for t in to_remove:
      self.log.debug("Removing closed thread '%s'." % t)
      del self.threads[t]
