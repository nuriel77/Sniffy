# Fire up a thread which checks
# the iptables logs and tries to
# match src and dst IP for packets
# earlier matched by inspection.
# Save results in database. When
# limit reached, sends out email
import re
import os
import sys
import time
import datetime
import hashlib
import threading
from pwd import getpwuid
from sniffy.utils.emailer import EmailNotification
from sniffy.utils.shell import run_cmd

log_entry_diff = int(os.environ['LOG_ENTRY_MAX_AGE']) if os.environ.get('LOG_ENTRY_MAX_AGE') else 180
email_wait_time = int(os.environ['EMAIL_WAIT_TIME']) if os.environ.get('EMAIL_WAIT_TIME') else 3600

"""
Class running as thread to parse
the iptables log and find matches,
extract UID and notify
"""
class IptablesThread(threading.Thread):
  def __init__(self, **kwargs):
    threading.Thread.__init__(self)
    self.log = kwargs['log']
    self.dbh = kwargs['dbh']
    self.t = kwargs['t']
    self.src_ip = kwargs['src_ip']
    self.dst_ip = kwargs['dst_ip']
    self.path = kwargs['path']
    self.method = kwargs['method']
    self.payload = kwargs['payload']
    self.threshold = kwargs['threshold']
    self.email = kwargs['email']
    self.time_regex = r"^\[\s*(\d+\.\d+)\]"

  def run(self):
    global log_entry_diff

    time.sleep(2)
    self.log.info("IptablesThread*: Searching dmesg for source and destination IP matches")    
    counter = 0
    matches = {}

    """
    Inspecting the logs we will find multiple lines.
    Let's check that the time difference between the last
    packet we inspected is around the time of the logged
    lines. Also, log counter per UID, though this will
    rarely (if ever) happen that multiple offending users
    will be found calling the same src/dst.
    """
    rc, out, err = run_cmd('dmesg -s 128000')
    if rc != 0:
      self.log.error("Error dmesg exit code %s: %s" % (rc, err))
      return

    lines = out.split('\n')
    for line in reversed(lines):
      if "OUTBOUND HTTP" and "SRC="+self.src_ip+" DST="+self.dst_ip in line:
        self.log.debug("IptablesThread*: Found match line: %s" % line.rstrip())
        # Get timestamp which is seconds
        # since system uptime
        m = re.search(self.time_regex, line)
        if not m:
          self.log.warning("IptablesThread*: Failed to get timestamp from dmesg line '%s'" % line)
          continue
        since_timestamp = m.group(1)
        uptime = get_uptime()
        uptime_timestamp = time.time() - uptime
        log_timestamp = uptime_timestamp + float(since_timestamp)
        log_timestamp_obj = datetime.datetime.fromtimestamp(log_timestamp)
        self.log.debug( "IptablesThread*: Log line time: %s " \
                    % (log_timestamp_obj.strftime('%b %d %Y %H:%M:%S')) )

        # Time of packet which triggered threhold
        # minus the time of logged iptables line
        diff = int(self.t) - int(log_timestamp)
        self.log.debug("IptablesThread*: Time diff is: %s" % diff)

        # If match is not older than (n) seconds...
        if diff <= log_entry_diff:
          counter += 1
          uid = None
          try:
            uid = re.search('.*UID=([0-9]+).*$', line).group(1)
          except AttributeError:
            self.log.warning("IptablesThread*: Cannot get UID from line?! '%s'" % line.rstrip())
            exit(1)
          user = getpwuid(int(uid)).pw_name
          matches[user] = counter
          self.log.debug("IptablesThread*: Offending UID is '%s' (%s)" % (uid, user))

        # The only purpose here is to avoid parsing the
        # entire log, we're only interested in a few
        # matches which are no older than (n) seconds
        # difference from last packet we matched.
        # Due to rate limiting in iptables logs there's
        # no guarantee that we can match all packets to
        # the number of logged lines.
        if counter >= self.threshold: break

    for u in matches:
      self.log.info("IptablesThread*: Found at least %s log matches for '%s'"
                 % (matches[u], u))

      if not self._check_email_sent(u):
        EmailNotification(self.email).send_mail(u, str(matches[u]), self)


  def _check_email_sent(self, user):
    global email_wait_time

    m = hashlib.md5()
    m.update("%s_%s" % (user, self.dst_ip))
    offender_sig = m.hexdigest()
    self.log.debug("IptablesThread*: Offender signature: '%s'" % offender_sig)

    dbh = self.dbh.connect()

    # Try to get an already existing offenders signature
    result = None
    try:
      result = dbh.exists(offender_sig)
    except AttributeError, e:
      self.log.error("IptablesThread*: DB error: %s", e)
      exit(1)
    except:
      self.log.error("IptablesThread*: DB error: %s", sys.exc_info()[0])
      return False

    if not result:
      dbh.setex(offender_sig, 1, email_wait_time)
      self.log.info("IptablesThread*: Offender '%s' email notification sent \
to '%s' and registered in DB" % (user, self.email))
      return False
    else:
      self.log.info("IptablesThread*: Offender '%s' email notification already sent" % user)
      return True

def get_uptime():
  with open('/proc/uptime', 'r') as f:
    return float(f.readline().split()[0])
