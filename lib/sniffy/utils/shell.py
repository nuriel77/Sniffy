import sys
import shlex
import shutil
from subprocess import Popen, PIPE

def run_cmd(cmd, shell=False):
  """
  Execute the external command and get its
  exitcode, stdout and stderr.
  """
  args = None
  if shell == True:
    args = cmd
  else:
    args = shlex.split(cmd)

  proc = None
  try:
    proc = Popen(args, stdout=PIPE, stderr=PIPE, shell=shell)
  except OSError, e:
    sys.stderr.write("Error executing command '%s': %s\n" % (cmd, e))
    sys.exit(1)

  out, err = proc.communicate()
  exitcode = proc.returncode
  return exitcode, out, err
