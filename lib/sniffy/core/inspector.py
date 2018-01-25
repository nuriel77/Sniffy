# -*- coding: utf-8 -*-
# Inspects HTTP packages if match
# signatures, then returns
# data for further processing

import re
import sys
import time
import gzip
from hashlib import md5
from StringIO import StringIO

"""
Try to import ipaddress and show error w/ install
instructions if it cannot be imported
"""
try:
  import ipaddress
except ImportError:
  sys.stderr.write("ERROR: You must have ipaddress installed.\n")
  sys.stderr.write("You can install it by running: sudo pip install ipaddress\n")
  exit(1)

class Parse:
  """Parse scapy packet

  Get the data we need. In case packets are
  fragmented, try to reassemble their payload.

  """
  def __init__(self, log, args, IP, sh, mc):
    self.log = log
    self.args = args
    self.match = mc                   # Match class object
    self.IP = IP                      # Scapy's IP class
    self.sh = sh                      # Scapy http class
    self.save_request = {}            # Save HTTPRequest
    self.fragments = {}               # Save fragment buckets
    self.blocked = {}                 # Save blocked fragment series
    self.force_last_pkt = False       # Declare last packet
    self.max_block_time = 5           # Max block time for rate limiting fragments
    self.max_bucket_age = 20          # Max bucket age, will be erased
    self.max_bucket_size = 10         # Max fragments to collect in bucket

  def parse_output(self, out):
    """Parse packet received by scapy sniff

    Each packet that enters here is inspected for its data
    such as src/dst IP, method, path and payload. If the
    packet is a fragment it will be checked whether it is
    the first packet. If first, it will be appended to a
    unique bucket. Subsequent related fragmented packets
    will be appended to the bucket until the last one.
    When the last one arrives we run algorithm to reassemble
    the payload into one string and return the data for further
    processing. If the packet is not part of fragmantation
    and has payload (on HTTP layer) it will be returned
    rightaway for further processing.

    - **parameters**, **types**

      :param out: packet received by scapy sniff
      :type out: <class 'scapy.layers.inet.IP'>
      :return: return keywords: skip(bool), msg(str) or request(dict)
      :rtype: dict

    - **variables**, **types**

      :var request: HTTPRequest data
      :var payload: Payload received
      :var force_last_pkt: Force fragment to be "last"
      :var bucket_key: Key for fragments bucket
      :var first_pkt: First pkt of fragments serie
      :type request: dict
      :type payload: str
      :type force_last_pkt: bool
      :type bucket_key: str
      :type first_pkt: <class 'scapy.layers.inet.IP'>
      
    """

    out.show()

    # Prepare dict
    request = {
      'dst_ip': None,
      'src_ip': None,
      'method': None,
      'path': None,
      'host': None,
      'payload': None,
      'time': int(time.time())}

    # Clean up old buckets if any remaining
    # and more than 3 buckes in dict
    if len(self.fragments) > 3:
      self._clean_old_buckets()

    # Get src/dst IP
    if out.haslayer(self.IP):
      request['dst_ip'] = u''+out[self.IP].dst
      request['src_ip'] = u''+out[self.IP].src

      # Have we dport attribute?
      try:
        out[self.IP].dport
      except:
        pass
      else:
        # Is a reply packet, switch dst/src
        # for bucket key and later check match
        if int(out[self.IP].dport) != 80:
          request['dst_ip'] = u''+out[self.IP].src
          request['src_ip'] = u''+out[self.IP].dst
    else:
      return dict(skip=True, msg="No IP layer found in packet?!")

    # Create bucket key. It is used to store a serie
    # of fragmented packets if we get any fragments.
    bucket_key = md5("%s_%s" % (request['src_ip'], request['dst_ip'])).hexdigest()
    payload = ''

    # Check if this serie is temporarily blocked. We block in case 
    # we get too many pkts and we don't want to process all.
    if self.blocked.has_key(bucket_key):
      pkg_time = self.blocked[bucket_key]
      now = time.time()
      time_diff = now - pkg_time
      if time_diff < self.max_block_time:
        return dict(skip=True, msg=None)
      else:
        self.log.debug("Removed rate limit block from bucket '%s'" % bucket_key)
        del self.blocked[bucket_key]

    # first_pkt gets populated by _check_fragment
    # when the last packet is processed and the
    # payload assembled from all fragments.
    # The first pkt contains the HTTP header
    first_pkt = None

    # Used to force a pkt to be regarded as the last
    # one. This is done when there are too many pkts
    # flowing in. We assume it is enough to get
    # payload from the first few pkts to be able
    # to match it to signatures/patterns
    self.force_last_pkt = False

    """ This is not a HTTPRequest, it is mosy likely a fragment """
    if not out.haslayer(self.sh.HTTPRequest):
      # Check if any fragments already in bucket
      # because first pkt (HTTPRequest) should already
      # be in fragments unique bucket
      if self.fragments.has_key(bucket_key) and len(self.fragments[bucket_key]['frags']) > 0:

        # Have a limit on how many fragments we collect
        if len(self.fragments[bucket_key]['frags']) > (self.max_bucket_size - 1):
          self.log.warning("Enough fragments collected for bucket '%s'" % bucket_key)

          # Register block time
          self.blocked[bucket_key] = request['time']

          # Force this to be last pkt so
          # that payload assembly kicks in
          self.force_last_pkt = True
          
        # Append fragment to already existing bucket or
        # if last fragment go ahead and assemble payload
        p = self._check_fragment(out, bucket_key, self.force_last_pkt)

        # _check_fragment only returns payload when
        # last package was detected, then payload will be
        # an assembly of payloads from all previous fragments.
        if type(p) is dict and p.has_key('payload'):
          payload = p['payload']
          first_pkt = p['first_pkt']
        else:
          return dict(skip=True, msg=None)

    """ Looks like pkt with MF flag (more fragments to come) """
    if self.force_last_pkt == False and (out[self.IP].flags == 1 or out[self.IP].frag > 0):

      # If this ever happens, just overwrite
      if self.fragments.has_key(bucket_key) and len(self.fragments[bucket_key]['frags']):
        self.log.warning("Bucket key '%s' already exists with previous %d packet(s). Rewriting..."
                      % (bucket_key, len(self.fragments[bucket_key]['frags'])))

      # Allow only HTTPRequest readable headers
      # to be stored as first packet of fragments serie
      if out.haslayer(self.sh.HTTPRequest):
        self.log.debug("Fragmented HTTPRequest Packet, start appending to bucket key '%s'" % bucket_key)
        self.fragments[bucket_key] = {
          'time': request['time'],
          'frags': [out]}

        # Populate array with first packet
        # Subsequent pkts belonging to this serie
        # will also be appended until last one.
        self.fragments[bucket_key]['frags'] = [out]

      # For now return nothing, waiting for last packet...
      return dict(skip=True, msg=None)

    """
    Non a fragmented packet, just get payload as is.
    Payload can appear in request or in subsequent
    http packet.
    """
    if payload == '':
      if out.haslayer(self.sh.HTTPRequest):
        payload = out.getlayer(self.sh.HTTPRequest).payload
      elif out.haslayer(self.sh.HTTP):
        payload = out.getlayer(self.sh.HTTP)
    request['payload'] = payload

    """ 
    if first_pkt has data it means it returned from
    packet payload assembly of a fragmented serie of pkts
    """
    if first_pkt:
      self.log.debug("HTTPRequest packet fragments assembled for bucket '%s'" % bucket_key)
      # Verify last packet and first one
      # actually share the same src/dst IP
      if first_pkt[self.IP].dst != request['dst_ip'] \
      or first_pkt[self.IP].src != request['src_ip']:
        self.log.warning('*** Source/Destination IP mismatch for first and last fragments: ***')
        self.log.warning("first pkg src: %s, last pkg src: %s, first pkg dst: %s, last pkg dst: %s"
                      % (first_pkt[self.IP].src, request['src_ip'], first_pkt[self.IP].dst, request['dst_ip']))
        return dict(skip=True, msg="Source or destination mismatch")

      out = first_pkt

    # Get fields of interest
    if out.haslayer(self.sh.HTTPRequest):
      f = out.getlayer(self.sh.HTTPRequest).fields
      for p in [ 'Path', 'Host', 'Method' ]:
        if f.has_key(p): request[p.lower()] = f[p]

      # We save original request because
      # we might only see payload in subsequent
      # packet sent to remote server. We first
      # check if this Path is in signatures
      # otherwise there's no point saving it
      if self.match.check_path(request['path']):
        self.save_request[bucket_key] = request

      # Return the request dictionary
      # Will be processed further
      return dict(request=request)
    elif out.haslayer(self.sh.HTTPResponse):
      # Here we probably got a response from
      # the remote server. We can ignore it.
      #self.log.debug('***HTTPResponse')
      pass
    elif out.haslayer(self.sh.HTTP):
      # Check if this is a packet relating to
      # last HTTPRequest packet.
      if self.save_request.has_key(bucket_key) and len(self.save_request[bucket_key]):
        self.log.debug("HTTP packet, matched bucket_key '%s', combining previous request data" % bucket_key)
        pkt_request = self.save_request[bucket_key]
        pkt_request['payload'] = request['payload']
        del self.save_request[bucket_key]
        return dict(request=pkt_request)
    else:
      self.log.debug('***Non HTTP')
      pass

  def _check_fragment(self, out, bucket_key, force_last_pkt):
    """Check packet fragment

      Will append fragments to unique bucket. If last packet is
      in will send to assemble payload so that it can be
      processed further for signature pattern matches
    """

    # If fragment but not last fragment
    if out[self.IP].flags == 0:
      self.force_last_pkt = True
    elif out[self.IP].flags == 1 or out[self.IP].frag > 0:
      pass
    else:
      self.log.warning("Fragment with out frag? frag=%s" % out[self.IP].frag)
      return

    self.fragments[bucket_key]['frags'].append(out)
    self.log.debug("Found packet fragment, have %d fragments in bucket '%s'"
                % (len(self.fragments[bucket_key]['frags']), bucket_key))

    if self.force_last_pkt == True:
      if out.haslayer(self.sh.HTTPRequest):
        self.fragments[bucket_key]['frags'].append(out)

      self.log.debug("Last fragment, have total %d in bucket '%s'"
                  % (len(self.fragments[bucket_key]['frags']), bucket_key))

      # Save first packet as it contains HTTP header
      first_pkt = self.fragments[bucket_key]['frags'][0]
      payload = self._process_frags(self.fragments[bucket_key]['frags'])

      # Remove unique bucket
      if bucket_key in self.fragments: del self.fragments[bucket_key]

      # Return reassembled payload and first pkt
      return dict(payload=payload, first_pkt=first_pkt)

  def _process_frags(self, frags):
    """Process fragments payload

    Linux type policy for packet reassembly
    see: https://www.sans.org/reading-room/whitepapers/detection/ip-fragment-reassembly-scapy-33969
    """
    buffer=StringIO()
    for pkt in sorted(frags, key= lambda x:x[self.IP].frag, reverse=True):
        buffer.seek(pkt[self.IP].frag*8)
        buffer.write(pkt[self.IP].payload)
    return buffer.getvalue()

  def _clean_old_buckets(self):
    """ Clean up old buckets """
    to_del = []
    for i in self.fragments:
      age = int(time.time()) - self.fragments[i]['time']
      if age > self.max_bucket_age:
        self.log.debug("Deleting expired bucket '%s', is %d seconds old" % (i, age))
        to_del.append(i)

    for i in to_del: del self.fragments[i]        
  
class Match:
  """Check signature matches

    - Check if data matches loaded signatures
    - Check whitelisted IPs/ranges
    - When class is instantiated is will
      (re)load the signatures from file
  """
  def __init__(self, signatures, log):
    self.signatures = signatures
    self.log = log

  def check_path(self, path):
    for i in range(len(self.signatures)):
      if re.search(self.signatures[i]['uri'], path):
        return True

  def filter(self, data):
    self.log.debug("*** HTTP outbound request path: '%s', src: '%s', dst: '%s', method: '%s'" \
                % (data['path'], data['src_ip'], data['dst_ip'], data['method']))

    signatures = self.signatures

    for i in range(len(signatures)):
      # Check for uri match      
      uri_result = re.search(signatures[i]['uri'], data['path'])
      if not uri_result: continue

      # Convert/uncompress payload if needed
      payload = self._process_payload(data['payload'])
      if payload == None:
        self.log.warning("Failed to read payload from packet")
        continue

      # Check for payload match
      payload_result = re.search(signatures[i]['payload'], payload)
      if not payload_result: continue

      # Check for method match
      method_result = re.search(signatures[i]['method'], data['method'])
      if not method_result: continue

      # Check source/destination match
      match_dst = None
      match_src = None

      # First check if source is not white-listed
      if data['src_ip'] not in signatures[i]['allowed_src_ips']:
        # If not, check if source IP matches network
        if ipaddress.ip_address(data['src_ip']) in ipaddress.ip_network(signatures[i]['src_net']):
          self.log.debug("Source IP %s matches network %s" \
                      % (data['src_ip'], signatures[i]['src_net']))
          match_src = True
      else:
        self.log.debug("Source IP %s whitelisted." % data['src_ip'])
        continue

      # Firsts check if destination is not white-listed
      if data['dst_ip'] not in signatures[i]['allowed_dst_ips']:
        # If not, check if source IP matches network
        if ipaddress.ip_address(data['dst_ip']) in ipaddress.ip_network(signatures[i]['dst_net']):
          self.log.debug("Destination IP %s matches network %s" \
                      % (data['dst_ip'], signatures[i]['dst_net']))
          match_dst = True
      else:
        self.log.debug("Destination IP %s whitelisted." % data['dst_ip'])
        continue

      # Check if all of the above checks are true, then process with db
      if uri_result and payload_result and match_src and match_dst and method_result:
        self.log.debug("Matched path '%s', method '%s' and payload '%s' for signature name '%s'" \
                    % (data['path'], data['method'], payload, signatures[i]['name']))
      else:
        continue

      return dict(data=data, uri_result=uri_result.group(1))

  def _process_payload(self, raw_payload):
    """Process the payload

      Payload might be gzip data or utf-8
      Sometimes we might get header binary
      data from previously fragmented payload.
    """
    payload = ''
    try:
      # For utf-8 type
      payload = unicode(str(raw_payload), "utf-8")
    except UnicodeDecodeError:
      try:
        # For compressed type
        payload = gzip.GzipFile(fileobj=StringIO(raw_payload)).read().rstrip()
      except IOError, e:
        self.log.warning("Cannot gzip read packet: %s, will extract ascii only." % e)
        payload = re.sub(r'[^\x00-\x7f]',r'', raw_payload) 
      except Exception, e:
        self.log.warning("Failed to process packet: %s" % e)
        return None
    return payload
