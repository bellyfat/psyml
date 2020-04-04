#!/usr/bin/env python3
"""Encapsulated AWS utility functions."""
import base64

import boto3

from .settings import PSYML_KEY_REGION, PSYML_KEY_ALIAS


_KMS = boto3.client("kms", region_name=PSYML_KEY_REGION)


def decrypt_with_psyml(name, encrypted):
    """Decrypt encrypted text with KMS."""
    return _KMS.decrypt(
        CiphertextBlob=base64.b64decode(encrypted),
        EncryptionContext={"Client": "psyml", "Name": name},
    )["Plaintext"].decode()


def encrypt_with_psyml(name, plaintext):
    """Encrypt plain text with KMS."""
    return base64.b64encode(
        _KMS.encrypt(
            KeyId=get_psyml_key_arn(),
            Plaintext=plaintext.encode(),
            EncryptionContext={"Client": "psyml", "Name": name},
        )["CiphertextBlob"]
    ).decode()


def get_psyml_key_arn():
    """Return the Arn of the psyml key."""
    return _KMS.describe_key(KeyId=PSYML_KEY_ALIAS)["KeyMetadata"]["Arn"]
