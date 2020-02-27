#!/usr/bin/env python3
import os
import unittest

import boto3
from moto import mock_kms

from psyml.awsutils import (
    decrypt_with_psyml,
    encrypt_with_psyml,
    get_psyml_key_arn,
)
from psyml.settings import PSYML_KEY_REGION, PSYML_KEY_ALIAS


class TestAWSUtils(unittest.TestCase):
    @mock_kms
    def kms_setup(self):
        conn = boto3.client("kms", region_name=PSYML_KEY_REGION)
        key = conn.create_key(Description="my key", KeyUsage="ENCRYPT_DECRYPT")
        self.conn = conn
        self.key_arn = key["KeyMetadata"]["Arn"]
        conn.create_alias(AliasName=PSYML_KEY_ALIAS, TargetKeyId=self.key_arn)

    @mock_kms
    def test_get_psyml_key_arn(self):
        self.kms_setup()
        self.assertEqual(get_psyml_key_arn(), self.key_arn)

    @mock_kms
    def test_encrypt_decrypt(self):
        self.kms_setup()
        encrypted = encrypt_with_psyml("some-name", "plaintext")
        self.assertNotEqual(encrypted, "plaintext")
        decrypted = decrypt_with_psyml("some-name", encrypted)
        self.assertEqual(decrypted, "plaintext")

        with self.assertRaises(self.conn.exceptions.InvalidCiphertextException):
            decrypt_with_psyml("another-name", encrypted)
