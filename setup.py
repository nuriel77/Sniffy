#!/usr/bin/env python

import os
import sys

sys.path.insert(0, os.path.abspath('lib'))
from sniffy import __version__, __author__
try:
  from setuptools import setup, find_packages
except ImportError:
  print("Sniffy needs setuptools in order to build. Install it using"
        " your package manager (usually python-setuptools) or via pip (pip"
        " install setuptools).")
  sys.exit(1)

# Get the long description from the README file
long_description = """
Sniffy: Program to inspect HTTP packets for potential abusers.
        Matching certain patterns and registering results to
        database. When limit/threshold is reached will alert
        by sending email with the information.
"""

setup(name='sniffy',
      version=__version__,
      author=__author__,
      description='Inspect HTTP packets to find potential abusers',
      long_description=long_description,
      author_email='nurielst@hotmail.com',
      url='https://github.com/nuriel77/Sniffy',
      install_requires=['paramiko', 'jinja2', "PyYAML", 'setuptools', 'python-daemon',
                        'ipaddress', 'scapy>=2.3,<2.4', 'scapy_http', 'argparse'
      ],
      package_dir={ '': 'lib' },
      packages=find_packages('lib'),
      classifiers=[
        'Development Status :: 1 - Production/Stable',
        'Environment :: Console',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2.7',
        'Topic :: System :: Systems Administration',
        'Topic :: Utilities',
      ],
      scripts=[
        'bin/sniffy',
      ],
      options={'bdist_rpm': {'install_script': 'files_install'}},
)
