# Description

Program to inspect HTTP packets for potential abusers.
Matching certain patterns and registering results to
database. When limit/threshold is reached will alert
by sending email with the information. Can be expended
to allow other actions.


Repository for Sniffy

# INSTALLATION (not via RPM)
```bash
python setup.py install
```

Uninstall:
```bash
pip uninstall sniffy
```
(might need to execute this twice)

For RPM via Jenkins:
```bash
python setup.py sdist -d SOURCES
```
Then tar creates in `SOURCES/sniffy-[version].tar.gz`

Bump release in SPECS/sniffy.spec, commit and push


# Configuration

Once installed (if via RPM) all files should be in place:

* /etc/init.d/sniffy              -> {start|stop|restart|condrestart|reload|status}  (sources /etc/sniffy/defaults)
* /etc/sniffy/db.creds.yml        -> Check that credentials and conncetion details are correct
* /etc/sniffy/defaults            -> Update email (NOTIFY="...") of required
* /etc/sniffy/signatures.yml      -> Update patterns or IP/ranges if required
* /etc/logrotate.d/sniffy         -> logrotate config

# Overview

Once installed via yum ( yum install sniffy ) will add the service to chkconfig and startup. Can verify it via `service sniffy status` .

Establishes connection with redis server as per `/etc/sniffy/db.creds.yml`

Debug is optional via `/etc/sniffy/defaults` (DEBUG="-d") and restart sniffy.

Log file in `/var/log/sniffy.log`

Signatures can be updated and sniffy reloaded to start using the new signatures: `service sniffy reload`

To test, can run a curl request to a certain host using one of the patterns specified in the signatures file.
For example:
```bash
sudo -u nuriel.shemtov curl -X POST -d '{"username":"xyz","password":"xyz"}' http://x-vps.com/wp-login
```
Note that only non root users are logged in iptables.
After having run the calls more than the threshold (5 times by default within 7 seconds) there should be an email sent to the address specified in NOTIFY="..." in the `/etc/sniffy/defaults` file.

Instead of checking the kernel-debug.log (where iptables should be logging) sniffy is checking dmesg because kernel-debug.log might miss some calls from time to time.

Most HTTP calls will contain the HTTPRequest together with the payload. Sometimes applications will only send HTTPRequest without the payload, only to be followed by another HTTP packet containing the payload. Sniffy keeps track of those and combines the payload with the initial HTTPRequest to find any offending patterns.
