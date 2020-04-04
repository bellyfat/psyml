#!/usr/bin/env python3
"""Core models for psyml package."""
import shlex

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
        """Return a list of AWS resouce Tags."""
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
        if self.encrypted_with:
            encrypted_with = self.encrypted_with
        else:
            encrypted_with = get_psyml_key_arn()
        data = {
            "path": self.path,
            "region": self.region,
            "kmskey": self.kmskey,
            "encrypted_with": encrypted_with,
        }

        if self.tags is not None:
            data["tags"] = self.tags

        data["parameters"] = [param.encrypted for param in self.parameters]
        print(yaml.dump(data, sort_keys=False, default_flow_style=False))

    def save(self):
        """Save items into Parameter store."""
        for param in self.parameters:
            SSMParameterStoreItem(self, param).save()

    def nuke(self):
        """Save remove all Parameter store items."""
        for param in self.parameters:
            SSMParameterStoreItem(self, param).delete()

    def decrypt(self):
        """Generate a yml file with all values decrypted."""
        data = {"path": self.path, "region": self.region, "kmskey": self.kmskey}

        if self.tags is not None:
            data["tags"] = self.tags

        data["parameters"] = [param.decrypted for param in self.parameters]
        print(yaml.dump(data, sort_keys=False, default_flow_style=False))

    def refresh(self):
        """Re-encrypt all values previously encrypte using an old key."""
        if get_psyml_key_arn() == self.encrypted_with:
            raise ValueError("PSYML key not refreshed, nothing to do")

        data = {
            "path": self.path,
            "region": self.region,
            "kmskey": self.kmskey,
            "encrypted_with": get_psyml_key_arn(),
        }

        if self.tags is not None:
            data["tags"] = self.tags

        data["parameters"] = [param.re_encrypted for param in self.parameters]
        print(yaml.dump(data, sort_keys=False, default_flow_style=False))

    def export(self):
        """
        Print bash export lines for all values that is ready to be sourced.
        """
        for parameter in self.parameters:
            print(parameter.export)

    def diff(self):
        """
        Find missing ones
        Find extra ones
        Find value changes
        Find tag changes
        """
        raise NotImplementedError

    def sync(self):
        """To be implemented."""
        raise NotImplementedError


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
        """Retuen a dict for this parameter with value encrypted."""
        if self.type_ == "SecureString":
            value = encrypt_with_psyml(self.name, self.value)
        else:
            value = self.value
        return {
            "name": self.name,
            "description": self.description,
            "value": value,
            "type": self.type_.lower(),
        }

    @property
    def re_encrypted(self):
        """Retuen a dict for this parameter with value encrypted."""
        if self.type_.lower() == "string":
            value = self.value
        else:
            value = encrypt_with_psyml(self.name, self.decrypted_value)
        return {
            "name": self.name,
            "description": self.description,
            "value": value,
            "type": self.type_.lower(),
        }

    @property
    def decrypted(self):
        """Retuen a dict for this parameter with value decrypted."""
        types = {"securestring": "SecureString", "string": "String"}
        return {
            "name": self.name,
            "description": self.description,
            "value": self.decrypted_value,
            "type": types.get(self.type_, self.type_),
        }

    @property
    def decrypted_value(self):
        """Retuen decrypted value for this parameter."""
        if self.type_ == "securestring":
            return decrypt_with_psyml(self.name, self.value)
        return self.value

    @property
    def export(self):
        """Return an export line for this value that can be source by bash."""
        return (
            f"export {self.name.replace('/', '_').replace('-', '_').upper()}"
            f"={shlex.quote(self.decrypted_value)}"
        )


class SSMParameterStoreItem:
    """An AWS SSM parameter store item."""

    def __init__(self, psyml, param):
        self.psyml = psyml
        self.data = param
        self.ssm = boto3.client("ssm", region_name=self.psyml.region)

    @property
    def path(self):
        """Return the ssm path of this item."""
        return self.psyml.path + self.data.name

    def __repr__(self):
        """Return a nice expression for this item."""
        return f"<SSMParameterStoreItem: {self.path}>"

    def save(self):
        """Save this item to parameter store."""
        kwargs = {
            "Name": self.path,
            "Description": self.data.description,
            "Value": self.data.decrypted_value,
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
        """Delete this item from parameter store."""
        self.ssm.delete_parameter(Name=self.path)
