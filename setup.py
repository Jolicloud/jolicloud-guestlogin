#!/usr/bin/python
# -*- coding: utf-8 -*-
from distutils.core import setup

setup(name='guestlogin',
      version='0.2',
      description="A PAM Module for allow guest users to login.",
      long_description="The Module creates a new user and gives it to a guest user.",
      author='Mesutcan Kurt',
      author_email='mesutcank@gmail.com',
      url='http://www.pardus.org.tr',
      license="GPLv2",
      platforms=["Linux"],
      data_files=[('/lib/security', ['guestlogin.py']),
                  ('/etc/security', ['guestlogin.conf']),
                  ('/etc/pam.d/', ['pam.d/guestlogin'])
                  ]
     )



