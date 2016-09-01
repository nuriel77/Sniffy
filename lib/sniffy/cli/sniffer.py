# Sniffer cli called by sniffy script (bin/sniffy)
# Will call argument parser, set logger object,
# daemonize if required and set signal handlers
import os
import sys
import signal
from sniffy import constants as C
from sniffy.utils.parser import parse_arguments
from sniffy.utils.logger import Log
import sniffy.core.engine

"""
Try to import daemon and show error w/ install
instructions if it cannot be imported
"""
try:
  import daemon
except ImportError:
  sys.stderr.write("ERROR: You must have python-daemon installed.\n")
  sys.stderr.write("You can install it by running: sudo pip install python-daemon\n")
  exit(1)

def run():
  global log
  global sniffer

  # Parse command line arguments
  args = parse_arguments()

  # Instantiate log class
  logger = Log(args.logfile)
  log = logger.set_logger()
  handler = logger.get_handler()

  # Add stdout logging when not daemonizing
  if not args.daemonize: logger.log_to_console()

  # Instantiate sniffy core engine
  sniffer = sniffy.core.engine.Sniffy(args, log)

  # Set logger debug if requested
  if args.debug: logger.set_debug()

  # Daemon?
  if args.daemonize:
    context = daemon.DaemonContext()

    # Preserve logger handler
    context.files_preserve = [handler.stream]

    # Set signal handlers
    context.signal_map = {
      signal.SIGTERM: cleanup,
      signal.SIGHUP: cleanup,
      signal.SIGUSR1: reload_sniffer}
    # Daemonize
    with context:
      sniffer.start()
  else:
    # Set signal handlers when not daemonizing
    signal.signal(signal.SIGHUP, cleanup)
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGUSR1, reload_sniffer)
    sniffer.start()

def cleanup(signum, frame):
  global log
  if signum == 2:
    log.info("User aborted. Terminating.")
  else:
    log.info("%s caught. Terminating." % C.SIGNALS_TO_NAMES_DICT[signum])
  sys.exit(1)

def reload_sniffer(signum, frame):
  global log
  log.debug("%s caught. Reloading..." % C.SIGNALS_TO_NAMES_DICT[signum])
  sniffer.start(msg="Restarting sniffer...")
