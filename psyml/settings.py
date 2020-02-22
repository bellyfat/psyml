#!/usr/bin/env python3

import os

_defaults = {
    'PSYML_KEY_REGION': 'ap-southeast-2',
    'PSYML_KEY_ALIAS': 'alias/psyml',
}

for name in _defaults:
    globals()[name] = os.environ.get(name, _defaults[name])

del name, _defaults
