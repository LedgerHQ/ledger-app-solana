# Copyright (c) 2013 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

from __future__ import absolute_import

from setuptools import Command
from distutils.errors import DistutilsSetupError
import os
import json
import tempfile


class executable(Command):
    description = "create an executable"
    user_options = [
        ('debug', None, "build with debug flag"),
        ('data-files=', None, "data files to include"),
        ('package-version=', None, "package version")
    ]
    boolean_options = ['debug']

    def initialize_options(self):
        self.debug = 0
        self.data_files = ''
        self.package_version = '0'

    def finalize_options(self):
        self.cwd = os.getcwd()
        self.data_files = self.data_files.split()
        self.package_version = int(self.package_version)

    def run(self):
        if os.getcwd() != self.cwd:
            raise DistutilsSetupError("Must be in package root!")

        from PyInstaller.__main__ import run as pyinst_run

        os.environ['pyinstaller_data'] = json.dumps({
            'debug': self.debug,
            'name': self.distribution.get_name(),
            'long_name': os.environ['setup_long_name'],
            'data_files': self.data_files,
            'package_version': self.package_version
        })

        spec = tempfile.NamedTemporaryFile(suffix='.spec', delete=False)
        source = os.path.join(os.path.dirname(__file__), 'pyinstaller_spec.py')
        with open(source) as f:
            spec.write(f.read())
        spec_name = spec.name
        spec.close()
        pyinst_run([spec_name])
        os.unlink(spec_name)

        self.announce("Executable created!")
