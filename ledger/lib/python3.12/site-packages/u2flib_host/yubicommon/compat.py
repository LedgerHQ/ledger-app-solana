"""Compatibility constants and helpers for Python 2.x and 3.x.
"""

import sys

# NB If this module grows to more than a handful of items it is probably
#    to bite the bullet and depend on the six package.
__all__ = [
    'string_types',
    'binary_type',
    'text_type',
    'int2byte',
    'byte2int'
]

# Needed for isinstance() checks
# Same behaviour as six.string_types https://pythonhosted.org/six/#constants
if sys.version_info < (3, 0):
    # Python 2.x
    _PY2 = True
    string_types = (basestring,)  # noqa: F821
    binary_type = str
    text_type = unicode  # noqa: F821
else:
    # Python 3.x
    _PY2 = False
    string_types = (str,)
    binary_type = bytes
    text_type = str


def int2byte(i):
    if _PY2:
        return chr(i)
    return bytes((i,))


def byte2int(i):
    if _PY2:
        return ord(i)
    return i
