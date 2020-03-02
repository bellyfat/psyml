#!/usr/bin/env python3
import copy
import unittest

from psyml.models import Parameter

MINIMAL_PARAM = {
    "name": "some-name",
    "description": "some desc",
    "type": "String",
    "value": "some-value",
}


class TestParameter(unittest.TestCase):
    def setUp(self):
        """Monkey patch encrypt/decrypt methods to avoid KMS usage in tests."""
        de = lambda _, value: value.split("-")[1]
        en = lambda name, value: f"{name}^{value}"
        import psyml.models

        psyml.models.encrypt_with_psyml = en
        psyml.models.decrypt_with_psyml = de

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
        self.assertEqual(err.exception.args[0], "Invalid type for parameters")

    def test_invalid_field(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        del param["description"]
        with self.assertRaises(AssertionError) as err:
            Parameter(param)
        self.assertEqual(
            err.exception.args[0], "Invalid/missing parameter field"
        )
        param["description"] = "some desc"
        parameter = Parameter(param)
        self.assertEqual(parameter.description, "some desc")
        param["extra"] = "foo"
        with self.assertRaises(AssertionError) as err:
            Parameter(param)
        self.assertEqual(
            err.exception.args[0], "Invalid/missing parameter field"
        )

    def test_invalid_type(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        param["description"] = 3
        with self.assertRaises(AssertionError) as err:
            Parameter(param)
        self.assertEqual(err.exception.args[0], "Invalid parameter type")
        param["description"] = "test"
        param["type"] = "invalid-type"
        with self.assertRaises(AssertionError) as err:
            Parameter(param)
        self.assertEqual(err.exception.args[0], "Invalid type in parameter")

    def test_value_type_conversion(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        param["value"] = 3
        parameter = Parameter(param)
        self.assertEqual(parameter.value, "3")

    def test_encrypted_value(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        parameter = Parameter(param)
        self.assertEqual(parameter.encrypted_value, "some-value")

        param = copy.deepcopy(MINIMAL_PARAM)
        param["value"] = 42
        parameter = Parameter(param)
        self.assertEqual(parameter.encrypted_value, "42")

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "SecureString"
        parameter = Parameter(param)
        self.assertEqual(parameter.encrypted_value, "some-name^some-value")

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "securestring"
        parameter = Parameter(param)
        self.assertEqual(parameter.encrypted_value, "some-value")

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
        parameter = Parameter(param)
        self.assertEqual(parameter.decrypted_value, "value")

    def test_encrypted(self):
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

    def test_decrypted(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        parameter = Parameter(param)
        self.assertEqual(
            parameter.decrypted,
            {
                "name": "some-name",
                "description": "some desc",
                "type": "String",
                "value": "some-value",
            },
        )

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "securestring"
        parameter = Parameter(param)
        self.assertEqual(
            parameter.decrypted,
            {
                "name": "some-name",
                "description": "some desc",
                "type": "SecureString",
                "value": "value",
            },
        )

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "SecureString"
        parameter = Parameter(param)
        self.assertEqual(
            parameter.decrypted,
            {
                "name": "some-name",
                "description": "some desc",
                "type": "SecureString",
                "value": "some-value",
            },
        )

    def test_re_encrypted_value(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        parameter = Parameter(param)

        self.assertEqual(parameter.encrypted_value, "some-value")
        self.assertEqual(parameter.decrypted_value, "some-value")
        self.assertEqual(parameter.re_encrypted_value, "some-value")

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "securestring"
        parameter = Parameter(param)

        self.assertEqual(parameter.encrypted_value, "some-value")
        self.assertEqual(parameter.decrypted_value, "value")
        self.assertEqual(parameter.re_encrypted_value, "some-name^value")

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "SecureString"
        parameter = Parameter(param)

        self.assertEqual(parameter.encrypted_value, "some-name^some-value")
        self.assertEqual(parameter.decrypted_value, "some-value")
        self.assertEqual(parameter.re_encrypted_value, "some-name^some-value")

    def test_re_encrypted(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        parameter = Parameter(param)
        self.assertEqual(
            parameter.re_encrypted,
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
            parameter.re_encrypted,
            {
                "name": "some-name",
                "description": "some desc",
                "type": "securestring",
                "value": "some-name^value",
            },
        )

        param = copy.deepcopy(MINIMAL_PARAM)
        param["type"] = "SecureString"
        parameter = Parameter(param)
        self.assertEqual(
            parameter.re_encrypted,
            {
                "name": "some-name",
                "description": "some desc",
                "type": "securestring",
                "value": "some-name^some-value",
            },
        )

    def test_export(self):
        param = copy.deepcopy(MINIMAL_PARAM)
        parameter = Parameter(param)

        self.assertEqual(parameter.export, "export SOME_NAME=some-value")

        param = copy.deepcopy(MINIMAL_PARAM)
        param["value"] = "test'value"
        parameter = Parameter(param)

        self.assertEqual(
            parameter.export, """export SOME_NAME='test'"'"'value'"""
        )
