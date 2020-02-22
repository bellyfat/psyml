#!/usr/bin/env python3
import sys

import yaml

from .awsutils import decrypt_with_psyml, encrypt_with_psyml, get_psyml_key_id


class PSyml:
    """Represents a PSyml file."""

    def __init__(self, file):
        self.path = None
        self.region = None
        self.kmskey = None
        self.parameters = None
        self.tags = None
        self.encrypted_with = None

        self._validate(file.read())

    def _validate(self, yaml_data):
        """Sanity check for the yaml."""
        data = yaml.load(yaml_data)
        assert isinstance(data, dict)

        mandantory = {
            "path": str,
            "region": str,
            "kmskey": str,
            "parameters": list,
        }
        optional = {"tags": dict, "encrypted_with": str}
        allowed = list(optional.keys()) + list(mandantory.keys())
        for key in data:
            assert key in allowed

        for field in mandantory:
            assert field in data
            assert isinstance(data[field], mandantory[field])
        self.path = data["path"].rstrip("/") + "/"
        self.region = data["region"]
        self.kmskey = data["kmskey"]
        self.parameters = [Parameter(param) for param in data["parameters"]]

        for field in optional:
            if field in data:
                assert isinstance(data[field], optional[field])
        self.tags = data.get("tags")
        self.encrypted_with = data.get("encrypted_with")

    def encrypt(self):
        """Encrypt a yml file with default kms key"""
        data = {
            "path": self.path,
            "region": self.region,
            "kmskey": self.kmskey,
            "encrypted_with": self.encrypted_with
            if self.encrypted_with
            else get_psyml_key_id(),
        }

        if self.tags is not None:
            data["tags"] = self.tags

        data["parameters"] = [param.encrypted for param in self.parameters]
        print(yaml.dump(data, default_flow_style=False))

    def save(self):
        print("save")


class Parameter:
    def __init__(self, param):
        self.name = None
        self.description = None
        self.type_ = None
        self.value = None

        self._validate(self, param)

    def _validate(self, param):
        """Sanity check for the parameter store item in yaml."""
        assert isinstance(param, dict)

        mandantory = ["name", "description", "type", "value"]
        assert set(param) == set(mandantory.keys())

        for field in mandantory:
            assert isinstance(param[field], str)

        assert param["type"] in [
            "String",
            "SecureString",
            "string",
            "securestring",
        ]

        self.name = param["name"]
        self.description = param["description"]
        self.type_ = param["type"]
        self.value = param["value"]

    @property
    def encrypted(self):
        data = {"name": self.name, "description": self.description}
        if self.type_.islower():
            data["value"] = self.value
            data["type"] = self.type_
        elif self.type_ == "String":
            data["value"] = self.value
            data["type"] = self.type_.lower()
        else:
            data["value"] = encrypt_with_psyml(self.value)
            data["type"] = self.type_.lower()
        return data


class SSMParameterStoreItem:
    """An AWS SSM parameter store item."""
