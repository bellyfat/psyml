#!/usr/bin/env python3
import base64

import boto3

from .settings import PSYML_KEY_REGION, PSYML_KEY_ALIAS


_kms = boto3.client("kms", region_name=PSYML_KEY_REGION)


def decrypt_with_psyml(name, encrypted):
    return _kms.decrypt(
        CiphertextBlob=base64.b64decode(encrypted),
        EncryptionContext={"Client": "psyml", "Name": name},
    )["Plaintext"].decode()


def encrypt_with_psyml(name, plaintext):
    return base64.b64encode(
        _kms.encrypt(
            KeyId=get_psyml_key_arn(),
            Plaintext=plaintext.encode(),
            EncryptionContext={"Client": "psyml", "Name": name},
        )["CiphertextBlob"]
    ).decode()


def get_psyml_key_arn():
    return _kms.describe_key(KeyId=PSYML_KEY_ALIAS)["KeyMetadata"]["Arn"]
