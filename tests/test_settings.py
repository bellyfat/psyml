#!/usr/bin/env python3
import os
import sys
import unittest


class TestSettings(unittest.TestCase):

    def test_default_psyml_settings(self):
        from psyml.settings import PSYML_KEY_REGION, PSYML_KEY_ALIAS
        self.assertEqual(PSYML_KEY_REGION, 'ap-southeast-2')
        self.assertEqual(PSYML_KEY_ALIAS, 'alias/psyml')

    def test_override_psyml_settings(self):
        os.environ["PSYML_KEY_REGION"] = "us-west-2"
        os.environ["PSYML_KEY_ALIAS"] = "alias/my-alias"
        from psyml.settings import PSYML_KEY_REGION, PSYML_KEY_ALIAS
        self.assertEqual(PSYML_KEY_REGION, 'us-west-2')
        self.assertEqual(PSYML_KEY_ALIAS, 'alias/my-alias')

    def tearDown(self):
        del sys.modules["psyml.settings"]
