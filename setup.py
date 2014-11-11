#!/usr/bin/python

from distutils.core import setup

setup(name='swift-statstee',
      version='1.0',
      description='swift-statstee',
      author='Mark Seger',
      author_email='mark.seger@hp.com',
      url='https://github.com/markseger/swift-statstee',

      data_files=[('/usr/bin',['swift-statstee.py', 'swiftstat']),
                  ('/etc', ['swift-statstee.conf']),
                  ('/etc/init.d', ['swift-statstee']),
                  ('/usr/share/man/man1',['swift-statstee.1', 'swiftstat.1'])]
     )
