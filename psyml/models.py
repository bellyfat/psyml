#!/usr/bin/env python3
import sys

import boto3
import yaml

from .awsutils import decrypt_with_psyml, encrypt_with_psyml, get_psyml_key_arn


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
        data = yaml.safe_load(yaml_data)
        assert isinstance(data, dict), "Invalid yml file"

        mandantory = {
            "path": str,
            "region": str,
            "kmskey": str,
            "parameters": list,
        }
        optional = {"tags": dict, "encrypted_with": str}
        allowed = list(optional.keys()) + list(mandantory.keys())
        for key in data:
            assert key in allowed, "Invalid key in yml file"

        for field in mandantory:
            assert field in data, "Missing mandantory field"
            assert isinstance(
                data[field], mandantory[field]
            ), f"field `{field}` has invalid type"
        self.path = data["path"].rstrip("/") + "/"
        self.region = data["region"]
        self.kmskey = data["kmskey"]
        self.parameters = [Parameter(param) for param in data["parameters"]]

        for field in optional:
            if field in data:
                assert isinstance(
                    data[field], optional[field]
                ), f"field `{field}` has invalid type"
        self.tags = data.get("tags")
        self.encrypted_with = data.get("encrypted_with")

    def __repr__(self):
        return f"<PSyml: {self.path}>"

    @property
    def aws_tags(self):
        if self.tags is None:
            return None
        return [
            {"Key": key, "Value": self.tags[key]} for key in sorted(self.tags)
        ]

    ###############
    # Commands
    ###############
    def encrypt(self):
        """Encrypt a yml file with default kms key"""
        data = {
            "path": self.path,
            "region": self.region,
            "kmskey": self.kmskey,
            "encrypted_with": self.encrypted_with
            if self.encrypted_with
            else get_psyml_key_arn(),
        }

        if self.tags is not None:
            data["tags"] = self.tags

        data["parameters"] = [param.encrypted for param in self.parameters]
        print(yaml.dump(data, sort_keys=False, default_flow_style=False))

    def save(self):
        for param in self.parameters:
            SSMParameterStoreItem(self, param).save()

    def nuke(self):
        for param in self.parameters:
            SSMParameterStoreItem(self, param).delete()

    def decrypt(self):
        pass

    def diff(self):
        pass

    def refresh(self):
        pass

    def export(self):
        pass

    def sync(self):
        pass


class Parameter:
    """Represents an parameter item in PSyml file."""

    def __init__(self, param):
        self.name = None
        self.description = None
        self.type_ = None
        self.value = None

        self._validate(param)

    def _validate(self, param):
        """Sanity check for the parameter store item in yaml."""
        assert isinstance(param, dict), "Invalid type for parameters"

        mandantory = ["name", "description", "type", "value"]
        assert set(param.keys()) == set(
            mandantory
        ), "Invalid/missing parameter field"

        for field in mandantory:
            if field != "value":
                assert isinstance(param[field], str), "Invalid parameter type"

        assert param["type"] in [
            "String",
            "SecureString",
            "string",
            "securestring",
        ], "Invalid type in parameter"

        self.name = param["name"]
        self.description = param["description"]
        self.type_ = param["type"]
        self.value = str(param["value"])

    def __repr__(self):
        return f"<Parameter: {self.name}>"

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
            data["value"] = encrypt_with_psyml(self.name, self.value)
            data["type"] = self.type_.lower()
        return data

    @property
    def decrypted(self):
        if self.type_ == "securestring":
            return decrypt_with_psyml(self.name, self.value)
        else:
            return self.value


class SSMParameterStoreItem:
    """An AWS SSM parameter store item."""

    def __init__(self, psyml, param):
        self.psyml = psyml
        self.data = param
        self.ssm = boto3.client("ssm", region_name=self.psyml.region)

    @property
    def path(self):
        return self.psyml.path + self.data.name

    def __repr__(self):
        return f"<SSMParameterStoreItem: {self.path}>"

    def save(self):
        kwargs = {
            "Name": self.path,
            "Description": self.data.description,
            "Value": self.data.decrypted,
            "Type": self.data.type_,
            "Overwrite": True,
        }
        if self.data.type_ == "SecureString":
            kwargs["KeyId"] = self.psyml.kmskey
        self.ssm.put_parameter(**kwargs)
        if self.psyml.aws_tags is not None:
            self.ssm.add_tags_to_resource(
                ResourceType="Parameter",
                ResourceId=self.path,
                Tags=self.psyml.aws_tags,
            )

    def delete(self):
        self.ssm.delete_parameter(Name=self.path)
