# Instantiates DB handler, starts up
# scapy's packet inspector, loads
# signatures to match and passes
# packages to filter class
import os
import sys
import logging
from sniffy.utils.cfg_loader import load_sigs
from sniffy.core.inspector import Parse, Match
from sniffy.core.process import CheckDB
from sniffy.core.dbconnector import DBH
#import pprint

"""
Suppress scapy warning if no default route for IPv6.
This needs to be done before the import from scapy.
"""
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

"""
Try to import sniff from scapy.all and show error
 w/ install instructions if it cannot be imported.
"""
try:
  from scapy.all import sniff, IP
except ImportError:
  sys.stderr.write("ERROR: You must have scapy installed.\n")
  sys.stderr.write("You can install it by running: sudo pip install -U 'scapy>=2.3,<2.4'\n")
  exit(1)

"""
Try to import scapy_http.http and show error
 w/ install instructions if it cannot be imported.
"""
try:
  import scapy_http.http
except ImportError:
  sys.stderr.write("ERROR: You must have scapy-http installed.\n")
  sys.stderr.write("You can install it by running: sudo pip install scapy-http\n")
  exit(1)

class Sniffy():
  """Fireup sniffy engine

  Runs sniff from scapy to start capturing packets specified
  according to filters. Packets that pass scapy's filter are
  sent to be parsed, when data is exctracted they are sent
  to match filter to see if the data matches any of the
  signatures provided in the signatures file.
  """

  def __init__(self, args, log):
    self.args = args
    self.log = log
    self.match = None
    self.dbh = DBH(args.database, args.credsfile, log)
    self.checkdb = CheckDB(self.log, self.dbh)
    self.window = int(os.environ['REQUESTS_WINDOW']) if os.environ.get('REQUESTS_WINDOW') else 180
    self.threshold = int(os.environ['REQUESTS_THRESHOLD']) if os.environ.get('REQUESTS_THRESHOLD') else 5
    self.max_pkt_len = int(os.environ['MAX_PACKET_LENGTH']) if os.environ.get('MAX_PACKET_LENGTH') else 1500

  def start(self, msg="Sniffer starting up..."):    
    # Load signatures into Match class
    self.load_signatures()
    # Instantiate Parse class
    self.parser = Parse(self.log, self.args, IP, scapy_http.http, self.match)

    self.log.info(msg)
    self.log.debug("Interface: %s, Filter: %s, Count: %s" \
                % (self.args.interface, self.args.filter, self.args.count))

    """ Start up scapy's sniffer """
    sniff(iface=self.args.interface,
          promisc=False,
          filter=self.args.filter,
          lfilter=lambda x: x[IP].len <= self.max_pkt_len,
          prn=self._parse_output,
          store=0,
          count=self.args.count)

  """ Load pattern signatures to match """
  def load_signatures(self): 
    signatures = load_sigs(self.args.sigfile, self.log)
    if type(signatures) is dict and signatures.has_key('error'):
      self.log.error("Sig errors: %s" % signatures['error'])
      exit(1)

    self.match = Match(signatures, self.log)

  """ Parse packet output """
  def _parse_output(self, out):
    """Handle packet received by scapy

    This method is called by scapy's sniff on packets
    it finds. Packets will first be sent to parser
    to extract data (or try reassembly of multiple
    packet fragemnts). If data is returned from parser
    they are forwarded to class of match filter.

    - **parameters**, **types**

      :param out: Packet received by scapy
      :type out: <class 'scapy.layers.inet.IP'>

    - **variables, **types**
      :var data: Data parsed from packet
      :var result: Data returned by match filter
      :type data: dict
      :type result: dict

    """

    #pprint.pprint(out.getlayer(scapy_http.http.HTTPRequest).fields, indent=4, width=1)

    data = self.parser.parse_output(out)
    if type(data) is dict:
      if data.has_key('request'):
        return_request = data['request']
      elif data.has_key('skip') and data['skip'] == True:
        if data.has_key('msg') and data['msg']:
          self.log.debug("Skipped packet, msg=%s" % data['msg'])
        return
    else:
      return

    # Match to loaded signatures
    result = self.match.filter(return_request)
    if result == None:
      return

    kwargs = {'result': result,
              'dbh': self.dbh,
              'email': self.args.notify,
              'log': self.log,
              'window': self.window,
              'threshold': self.threshold}

    # Check DB, write to DB
    self.checkdb.check(**kwargs)
