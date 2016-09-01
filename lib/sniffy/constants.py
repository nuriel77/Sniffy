import signal
import socket

""" Get FQDN """
THIS_HOST = socket.getfqdn()

""" Translate signums to names """
SIGNALS_TO_NAMES_DICT = dict((getattr(signal, n), n) \
  for n in dir(signal) if n.startswith('SIG') and '_' not in n )

