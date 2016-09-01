# Loads signatures from file
# or database credentials
import re
import sys
import yaml

def load_sigs(sig_file, log):
  sigdata = None
  try:
    stream = open(sig_file, 'r')
  except IOError, e:
    return dict(error="Cannot read file '%s': %s" % (sig_file, e))

  sigdata = yaml.load(stream)
  log.debug("Loaded signatures: %s" % sigdata)

  # Process signatures, compile regex etc
  for i in range(len(sigdata)):
    if not sigdata[i].has_key('name') or sigdata[i]['name'] == None \
    or sigdata[i]['name'] == '':
      sigdata[i]['name'] = 'signature_%s' % i

    for key in ['method', 'uri', 'payload']:
      if sigdata[i].has_key(key):
        sigdata[i][key] = re.compile(r'('+sigdata[i][key]+')')
      else:
        sigdata[i][key] = re.compile(r'(.*)')

    for key in ['src_net', 'dst_net']:
      if sigdata[i].has_key(key):
        sigdata[i][key] = u'' + sigdata[i][key]
      else:
        sigdata[i][key] = u'0.0.0.0/0'

    for key in ['allowed_dst_ips', 'allowed_src_ips']:
      if not sigdata[i].has_key(key) or sigdata[i][key] == None:
        sigdata[i][key] = []

  return sigdata

def load_db_creds(creds_file):
  try:
    stream = open(creds_file, 'r')
  except IOError, e:
    return dict(error="Cannot read file '%s': %s" % (creds_file, e))
  return yaml.load(stream)
