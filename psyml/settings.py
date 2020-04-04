#!/usr/bin/env python3
"""Global settings for psyml."""
import os

PSYML_KEY_REGION = os.environ.get("PSYML_KEY_REGION", "ap-southeast-2")
PSYML_KEY_ALIAS = os.environ.get("PSYML_KEY_ALIAS", "alias/psyml")
