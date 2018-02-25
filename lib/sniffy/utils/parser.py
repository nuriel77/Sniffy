# Command line argument parser
# Added custom help formatter to allow
# display of longer lines without wrap
import argparse

def parse_arguments():
  # Set custom max width length for help output
  formatter_class=lambda prog: MyFormatter(prog, max_help_position=40, width=120)

  """ Parse command line arguments and make them available. """
  parser = argparse.ArgumentParser(
    formatter_class=formatter_class,
    description="Scan HTTP Request headers (must be run as root or with capabilities to sniff).",
  )
  parser.add_argument("--logfile", "-l", help="Log file", default="/var/log/sniffy.log")
  parser.add_argument("--credsfile", "-x", help="Database credentials file", default="./etc/sniffy/db.creds.yml")
  parser.add_argument("--sigfile", "-s", help="Signatures file", default="./etc/sniffy/signatures.yml")
  parser.add_argument("--interface", "-i", help="Which interface to sniff on.", default="eth0")
  parser.add_argument("--notify", "-n", help="Email to notify about offenders.", default="abuse-team-notify@someemail.cl")
  parser.add_argument("--database", "-b", help="Which database engine to use.", default="redis")
  parser.add_argument("--filter", "-f", help='BPF formatted packet filter.', default="tcp and port 80 or (ip[6:2] & 0x1fff) != 0")
  parser.add_argument("--count", "-c", help="Number of packets to capture. 0 is unlimited.", type=int, default=0)
  parser.add_argument("--debug", "-d", help="Debug", action="store_true", default=False)
  parser.add_argument("--daemonize", "-D", help="Daemonize", action="store_true", default=False)
  return parser.parse_args()

class MyFormatter(argparse.HelpFormatter):
  """
  Corrected _max_action_length for the indenting of subactions
  """
  def add_argument(self, action):
    if action.help is not argparse.SUPPRESS:
      if '%(default)' not in action.help:
        if action.default is not argparse.SUPPRESS:
          defaulting_nargs = [argparse.OPTIONAL, argparse.ZERO_OR_MORE]
          if action.option_strings or action.nargs in defaulting_nargs:
            action.help += ' (default: %(default)s)'

      # find all invocations
      get_invocation = self._format_action_invocation
      invocations = [get_invocation(action)]
      current_indent = self._current_indent
      for subaction in self._iter_indented_subactions(action):
        # compensate for the indent that will be added
        indent_chg = self._current_indent - current_indent
        added_indent = 'x'*indent_chg
        invocations.append(added_indent+get_invocation(subaction))
      # print('inv', invocations)

      # update the maximum item length
      invocation_length = max([len(s) for s in invocations])
      action_length = invocation_length + self._current_indent
      self._action_max_length = max(self._action_max_length,
                                    action_length)

      # add the item to the list
      self._add_item(self._format_action, [action])
