#!/usr/bin/env python3
import copy
import io
import unittest

import yaml

from psyml.models import PSyml, Parameter, SSMParameterStoreItem
from psyml.settings import PSYML_KEY_REGION, PSYML_KEY_ALIAS

MINIMAL_PSYML = {
    "path": "some-path",
    "region": "some-region",
    "kmskey": "some-kmskey",
    "parameters": [
        {
            "name": "some-name",
            "description": "some-desc",
            "type": "String",
            "value": "some-value",
        }
    ]
}
MINIMAL_PARAM = {
    "name": "some-name",
    "description": "some desc",
    "type": "String",
    "value": "some-value",
}

class TestPSyml(unittest.TestCase):
    def test_minimal_yaml(self):
        fobj = io.StringIO(yaml.dump(MINIMAL_PSYML))
        psyml = PSyml(fobj)
        self.assertEqual(str(psyml), "<PSyml: some-path/>")
        self.assertEqual(psyml.path, 'some-path/')
        self.assertEqual(psyml.region, 'some-region')
        self.assertEqual(psyml.kmskey, 'some-kmskey')
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
            psyml.aws_tags, [
                {"Key": "name", "Value": "abc"},
                {"Key": "order", "Value": "def"},
            ]
        )

    def test_validate_bad_yml(self):
        bad_type = [1, 2, 3, 4]
        fobj = io.StringIO(yaml.dump(bad_type))

        with self.assertRaises(AssertionError) as err:
            psyml = PSyml(fobj)
        self.assertEqual(err.exception.args[0], 'Invalid yml file')

    def test_validate_extra_field(self):
        with_extra_field = copy.deepcopy(MINIMAL_PSYML)
        with_extra_field["extra"] = "something"
        fobj = io.StringIO(yaml.dump(with_extra_field))

        with self.assertRaises(AssertionError) as err:
            psyml = PSyml(fobj)
        self.assertEqual(err.exception.args[0], 'Invalid key in yml file')

    def test_validate_missing_field(self):
        with_missing_field = copy.deepcopy(MINIMAL_PSYML)
        del with_missing_field["region"]
        fobj = io.StringIO(yaml.dump(with_missing_field))

        with self.assertRaises(AssertionError) as err:
            psyml = PSyml(fobj)
        self.assertEqual(err.exception.args[0], 'Missing mandantory field')

    def test_validate_bad_field_type(self):
        bad_field_type = copy.deepcopy(MINIMAL_PSYML)
        bad_field_type["region"] = 42
        fobj = io.StringIO(yaml.dump(bad_field_type))

        with self.assertRaises(AssertionError) as err:
            psyml = PSyml(fobj)
        self.assertEqual(
            err.exception.args[0], 'field `region` has invalid type'
        )

        bad_field_type = copy.deepcopy(MINIMAL_PSYML)
        bad_field_type["tags"] = True
        fobj = io.StringIO(yaml.dump(bad_field_type))
        with self.assertRaises(AssertionError) as err:
            psyml = PSyml(fobj)
        self.assertEqual(
            err.exception.args[0], 'field `tags` has invalid type'
        )


class TestParameter(unittest.TestCase):
    def test_minimal(self):
        param = Parameter(MINIMAL_PARAM)
        self.assertEqual(str(param), "<Parameter: some-name>")
        self.assertEqual(param.name, "some-name")
        self.assertEqual(param.description, "some desc")
        self.assertEqual(param.type_, "String")
        self.assertEqual(param.value, "some-value")

    def test_invalid_type(self):
        with self.assertRaises(AssertionError) as err:
            psyml = Parameter(["a", "b"])
        self.assertEqual(err.exception.args[0], 'Invalid type for parameters')

    def test_invalid_field(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        del param["description"]
        with self.assertRaises(AssertionError) as err:
            Parameter(param)
        self.assertEqual(err.exception.args[0], 'Invalid/missing parameter field')
        param["description"] = "some desc"
        parameter = Parameter(param)
        self.assertEqual(parameter.description, 'some desc')
        param["extra"] = "foo"
        with self.assertRaises(AssertionError) as err:
            Parameter(param)
        self.assertEqual(err.exception.args[0], 'Invalid/missing parameter field')

    def test_invalid_type(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        param["description"] = 3
        with self.assertRaises(AssertionError) as err:
            Parameter(param)
        self.assertEqual(err.exception.args[0], 'Invalid parameter type')
        param["description"] = "test"
        param["type"] = "invalid-type"
        with self.assertRaises(AssertionError) as err:
            Parameter(param)
        self.assertEqual(err.exception.args[0], 'Invalid type in parameter')

    def test_value_type_conversion(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        param["value"] = 3
        parameter = Parameter(param)
        self.assertEqual(parameter.value, "3")

    def test_decrypted_value(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        parameter = Parameter(param)
        self.assertEqual(parameter.decrypted_value, "some-value")

        param = copy.deepcopy(MINIMAL_PARAM)
        param["value"] = 42
        parameter = Parameter(param)
        self.assertEqual(parameter.decrypted_value, "42")

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "SecureString"
        parameter = Parameter(param)
        self.assertEqual(parameter.decrypted_value, "some-value")

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "securestring"
        import psyml.models
        join = lambda name, value: f"{name}%{value}"
        psyml.models.decrypt_with_psyml = join
        parameter = Parameter(param)
        self.assertEqual(parameter.decrypted_value, "some-name%some-value")

    def test_encrypted(self):
        join = lambda name, value: f"{name}^{value}"
        import psyml.models
        psyml.models.encrypt_with_psyml = join

        param = copy.deepcopy(MINIMAL_PARAM)
        parameter = Parameter(param)
        self.assertEqual(
            parameter.encrypted,
            {
                "name": "some-name",
                "description": "some desc",
                "type": "string",
                "value": "some-value",
            },
        )

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "securestring"
        parameter = Parameter(param)
        self.assertEqual(
            parameter.encrypted,
            {
                "name": "some-name",
                "description": "some desc",
                "type": "securestring",
                "value": "some-value",
            },
        )

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "SecureString"
        parameter = Parameter(param)
        self.assertEqual(
            parameter.encrypted,
            {
                "name": "some-name",
                "description": "some desc",
                "type": "securestring",
                "value": "some-name^some-value",
            },
        )
