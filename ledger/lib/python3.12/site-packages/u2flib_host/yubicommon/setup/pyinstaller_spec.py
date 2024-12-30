# -*- mode: python -*-
# -*- encoding: utf-8 -*-

# flake8: noqa

from __future__ import absolute_import
from __future__ import print_function

import os
import sys
import json
import errno
import pkg_resources
from glob import glob


VS_VERSION_INFO = """
VSVersionInfo(
  ffi=FixedFileInfo(
    # filevers and prodvers should be always a tuple with four
    # items: (1, 2, 3, 4)
    # Set not needed items to zero 0.
    filevers=%(ver_tup)r,
    prodvers=%(ver_tup)r,
    # Contains a bitmask that specifies the valid bits 'flags'r
    mask=0x0,
    # Contains a bitmask that specifies the Boolean attributes
    # of the file.
    flags=0x0,
    # The operating system for which this file was designed.
    # 0x4 - NT and there is no need to change it.
    OS=0x4,
    # The general type of file.
    # 0x1 - the file is an application.
    fileType=0x1,
    # The function of the file.
    # 0x0 - the function is not defined for this fileType
    subtype=0x0,
    # Creation date and time stamp.
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904E4',
        [StringStruct(u'FileDescription', u'%(name)s'),
        StringStruct(u'FileVersion', u'%(ver_str)s'),
        StringStruct(u'InternalName', u'%(internal_name)s'),
        StringStruct(u'LegalCopyright', u'Copyright © 2015 Yubico'),
        StringStruct(u'OriginalFilename', u'%(exe_name)s'),
        StringStruct(u'ProductName', u'%(name)s'),
        StringStruct(u'ProductVersion', u'%(ver_str)s')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1252])])
  ]
)"""

data = json.loads(os.environ['pyinstaller_data'])
try:
    data = dict((k, v.encode('ascii') if getattr(v, 'encode', None) else v)
                for k, v in data.items())
except NameError:
    pass  # Python 3, encode not needed.
dist = pkg_resources.get_distribution(data['name'])

DEBUG = bool(data['debug'])
NAME = data['long_name']

WIN = sys.platform in ['win32', 'cygwin']
OSX = sys.platform in ['darwin']

ver_str = dist.version
if data['package_version'] > 0:
    ver_str += '.%d' % data['package_version']
file_ext = '.exe' if WIN else ''

if WIN:
    icon_ext = 'ico'
elif OSX:
    icon_ext = 'icns'
else:
    icon_ext = 'png'
ICON = os.path.join('resources', '%s.%s' % (data['name'], icon_ext))

if not os.path.isfile(ICON):
    ICON = None

# Generate scripts from entry_points.
merge = []
entry_map = dist.get_entry_map()
console_scripts = entry_map.get('console_scripts', {})
gui_scripts = entry_map.get('gui_scripts', {})

for ep in list(gui_scripts.values()) + list(console_scripts.values()):
    script_path = os.path.join(os.getcwd(), ep.name + '-script.py')
    with open(script_path, 'w') as fh:
        fh.write("import %s\n" % ep.module_name)
        fh.write("%s.%s()\n" % (ep.module_name, '.'.join(ep.attrs)))
    merge.append(
        (Analysis([script_path], [dist.location], None, None, None, None),
         ep.name, ep.name + file_ext)
    )


MERGE(*merge)


# Read version information on Windows.
VERSION = None
if WIN:
    VERSION = 'build/file_version_info.txt'

    global int_or_zero  # Needed due to how this script is invoked

    def int_or_zero(v):
        try:
            return int(v)
        except ValueError:
            return 0

    ver_tup = tuple(int_or_zero(v) for v in ver_str.split('.'))
    # Windows needs 4-tuple.
    if len(ver_tup) < 4:
        ver_tup += (0,) * (4-len(ver_tup))
    elif len(ver_tup) > 4:
        ver_tup = ver_tup[:4]

    # Write version info.
    with open(VERSION, 'w') as f:
        f.write(VS_VERSION_INFO % {
            'name': NAME,
            'internal_name': data['name'],
            'ver_tup': ver_tup,
            'ver_str': ver_str,
            'exe_name': data['name'] + file_ext
        })

pyzs = [PYZ(m[0].pure) for m in merge]

exes = []
for (a, a_name, a_name_ext), pyz in zip(merge, pyzs):
    exe = EXE(pyz,
              a.scripts,
              exclude_binaries=True,
              name=a_name_ext,
              debug=DEBUG,
              strip=None,
              upx=True,
              console=DEBUG or a_name in console_scripts,
              append_pkg=not OSX,
              version=VERSION,
              icon=ICON)
    exes.append(exe)

    # Sign the executable
    if WIN:
        os.system("signtool.exe sign /fd SHA256 /t http://timestamp.verisign.com/scripts/timstamp.dll \"%s\"" %
                (exe.name))

collect = []
for (a, _, a_name), exe in zip(merge, exes):
    collect += [exe, a.binaries, a.zipfiles, a.datas]

# Data files
collect.append([(os.path.basename(fn), fn, 'DATA') for fn in data['data_files']])

# DLLs, dylibs and executables should go here.
collect.append([(fn[4:], fn, 'BINARY') for fn in glob('lib/*')])

coll = COLLECT(*collect, strip=None, upx=True, name=NAME)

# Write package version for app to display
pversion_fn = os.path.join('dist', NAME, 'package_version.txt')
with open(pversion_fn, 'w') as f:
    f.write(str(data['package_version']))

# Create .app for OSX
if OSX:
    app = BUNDLE(coll,
                 name="%s.app" % NAME,
                 version=ver_str,
                 icon=ICON)

    qt_conf = 'dist/%s.app/Contents/Resources/qt.conf' % NAME
    qt_conf_dir = os.path.dirname(qt_conf)
    try:
        os.makedirs(qt_conf_dir)
    except OSError as e:
        if not (e.errno == errno.EEXIST and os.path.isdir(qt_conf_dir)):
            raise
    with open(qt_conf, 'w') as f:
        f.write('[Path]\nPlugins = plugins')

# Create Windows installer
if WIN:
    installer_cfg = 'resources/win-installer.nsi'
    if os.path.isfile(installer_cfg):
        os.system('makensis.exe -D"VERSION=%s" %s' % (ver_str, installer_cfg))
        installer = "dist/%s-%s-win.exe" % (data['name'], ver_str)
        os.system("signtool.exe sign /fd SHA256 /t http://timestamp.verisign.com/scripts/timstamp.dll \"%s\"" %
                 (installer))
        print("Installer created: %s" % installer)
