#!/usr/bin/env python3
import copy
import io
import sys
import unittest
from contextlib import contextmanager

import boto3
import yaml
from moto import mock_kms, mock_ssm

from psyml.models import PSyml, Parameter
from psyml.settings import PSYML_KEY_REGION, PSYML_KEY_ALIAS


MINIMAL_PSYML = {
    "path": "some-path",
    "region": "us-west-1",
    "kmskey": "some-kmskey",
    "parameters": [
        {
            "name": "some-name",
            "description": "some-desc",
            "type": "String",
            "value": "some-value",
        }
    ],
}
MINIMAL_EXPORT = """path: some-path/
region: us-west-1
kmskey: some-kmskey
encrypted_with: {key_arn}
parameters:
- name: some-name
  description: some-desc
  value: some-value
  type: string
"""
MINIMAL_DECRYPT = """path: some-path/
region: us-west-1
kmskey: some-kmskey
{extra_tags}
parameters:
- name: some-name
  description: some-desc
  value: some-value
  type: String
{extra_params}
"""

# FIXME:
# PSyml.refresh
# PSyml.export


@contextmanager
def captured_output():
    new_out, new_err = io.StringIO(), io.StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class TestPSyml(unittest.TestCase):
    def test_minimal_yaml(self):
        fobj = io.StringIO(yaml.dump(MINIMAL_PSYML))
        psyml = PSyml(fobj)
        self.assertEqual(str(psyml), "<PSyml: some-path/>")
        self.assertEqual(psyml.path, "some-path/")
        self.assertEqual(psyml.region, "us-west-1")
        self.assertEqual(psyml.kmskey, "some-kmskey")
        self.assertEqual(len(psyml.parameters), 1)
        self.assertEqual(psyml.tags, None)
        self.assertEqual(psyml.encrypted_with, None)
        param = psyml.parameters[0]
        self.assertEqual(str(param), "<Parameter: some-name>")
        self.assertEqual(param.name, "some-name")
        self.assertEqual(param.description, "some-desc")
        self.assertEqual(param.type_, "String")
        self.assertEqual(param.value, "some-value")

    def test_aws_tags(self):
        fobj = io.StringIO(yaml.dump(MINIMAL_PSYML))
        psyml = PSyml(fobj)
        self.assertEqual(psyml.aws_tags, None)

        psyml.tags = {"name": "abc", "order": "def"}
        self.assertEqual(
            psyml.aws_tags,
            [{"Key": "name", "Value": "abc"}, {"Key": "order", "Value": "def"}],
        )

    def test_validate_bad_yml(self):
        bad_type = [1, 2, 3, 4]
        fobj = io.StringIO(yaml.dump(bad_type))

        with self.assertRaises(AssertionError) as err:
            psyml = PSyml(fobj)
        self.assertEqual(err.exception.args[0], "Invalid yml file")

    def test_validate_extra_field(self):
        with_extra_field = copy.deepcopy(MINIMAL_PSYML)
        with_extra_field["extra"] = "something"
        fobj = io.StringIO(yaml.dump(with_extra_field))

        with self.assertRaises(AssertionError) as err:
            psyml = PSyml(fobj)
        self.assertEqual(err.exception.args[0], "Invalid key in yml file")

    def test_validate_missing_field(self):
        with_missing_field = copy.deepcopy(MINIMAL_PSYML)
        del with_missing_field["region"]
        fobj = io.StringIO(yaml.dump(with_missing_field))

        with self.assertRaises(AssertionError) as err:
            psyml = PSyml(fobj)
        self.assertEqual(err.exception.args[0], "Missing mandantory field")

    def test_validate_bad_field_type(self):
        bad_field_type = copy.deepcopy(MINIMAL_PSYML)
        bad_field_type["region"] = 42
        fobj = io.StringIO(yaml.dump(bad_field_type))

        with self.assertRaises(AssertionError) as err:
            psyml = PSyml(fobj)
        self.assertEqual(
            err.exception.args[0], "field `region` has invalid type"
        )

        bad_field_type = copy.deepcopy(MINIMAL_PSYML)
        bad_field_type["tags"] = True
        fobj = io.StringIO(yaml.dump(bad_field_type))
        with self.assertRaises(AssertionError) as err:
            psyml = PSyml(fobj)
        self.assertEqual(err.exception.args[0], "field `tags` has invalid type")


class TestPSymlCommand(unittest.TestCase):
    def setUp(self):
        """Monkey patch encrypt/decrypt methods to avoid KMS usage in tests."""
        de = lambda _, value: value.split("-")[1]
        en = lambda name, value: f"{name}^{value}"
        import psyml.models

        psyml.models.encrypt_with_psyml = en
        psyml.models.decrypt_with_psyml = de

    @mock_kms
    def kms_setup(self):
        conn = boto3.client("kms", region_name=PSYML_KEY_REGION)
        key = conn.create_key(Description="my key", KeyUsage="ENCRYPT_DECRYPT")
        self.conn = conn
        self.key_arn = key["KeyMetadata"]["Arn"]
        conn.create_alias(AliasName=PSYML_KEY_ALIAS, TargetKeyId=self.key_arn)

    @mock_kms
    def test_encrypt_minimal(self):
        self.kms_setup()
        fobj = io.StringIO(yaml.dump(MINIMAL_PSYML))
        psyml = PSyml(fobj)
        with captured_output() as (out, err):
            psyml.encrypt()
        output = out.getvalue()
        self.assertEqual(
            output.strip(), MINIMAL_EXPORT.format(key_arn=self.key_arn).strip()
        )

    @mock_kms
    def test_encrypt_with_tags(self):
        self.kms_setup()
        fobj = io.StringIO(yaml.dump(MINIMAL_PSYML))
        psyml = PSyml(fobj)
        psyml.tags = {"tag-a": "value-a", "tag-b": "value-b"}
        with captured_output() as (out, err):
            psyml.encrypt()
        alt_psyml = PSyml(io.StringIO(out.getvalue().strip()))
        self.assertEqual(alt_psyml.tags, psyml.tags)

    @mock_kms
    def test_decrypt_minimal(self):
        self.kms_setup()
        fobj = io.StringIO(yaml.dump(MINIMAL_PSYML))
        psyml = PSyml(fobj)
        parameter = Parameter(
            {
                "name": "some-name",
                "description": "some-desc",
                "type": "securestring",
                "value": "some-value",
            }
        )
        psyml.parameters.append(parameter)
        psyml.tags = {"tag-a": "value-a", "tag-b": "value-b"}
        with captured_output() as (out, err):
            psyml.decrypt()
        output = out.getvalue()
        extra_yaml = (
            "- name: some-name\n"
            "  description: some-desc\n"
            "  value: value\n"
            "  type: SecureString"
        )
        extra_tags = "tags:\n" "  tag-a: value-a\n" "  tag-b: value-b"
        self.assertEqual(
            output.strip(),
            MINIMAL_DECRYPT.format(
                key_arn=self.key_arn,
                extra_params=extra_yaml,
                extra_tags=extra_tags,
            ).strip(),
        )

    @mock_kms
    @mock_ssm
    def test_save_and_nuke(self):
        ssm_no_use = boto3.client("ssm", region_name="us-gov-east-1")
        ssm = boto3.client("ssm", region_name="us-west-1")
        self.kms_setup()
        fobj = io.StringIO(yaml.dump(MINIMAL_PSYML))
        psyml = PSyml(fobj)
        psyml.save()
        parameter = ssm.get_parameters_by_path(
            Path="some-path/", Recursive=False
        )["Parameters"][0]
        self.assertEqual(parameter["Name"], "some-path/some-name")
        self.assertEqual(parameter["Type"], "String")
        self.assertEqual(parameter["Value"], "some-value")

        # Test nuke
        psyml.nuke()
        parameters = ssm.get_parameters_by_path(
            Path="some-path/", Recursive=False
        )["Parameters"]
        self.assertEqual(len(parameters), 0)
