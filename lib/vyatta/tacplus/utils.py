# Copyright (c) 2020 AT&T Intellectual Property.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

import sys

def print_err(*args):
    print(*args, file=sys.stderr)
