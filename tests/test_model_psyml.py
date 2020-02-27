#!/usr/bin/env python3
import copy
import io
import unittest

import yaml

from psyml.models import PSyml


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
    ],
}


class TestPSyml(unittest.TestCase):
    def test_minimal_yaml(self):
        fobj = io.StringIO(yaml.dump(MINIMAL_PSYML))
        psyml = PSyml(fobj)
        self.assertEqual(str(psyml), "<PSyml: some-path/>")
        self.assertEqual(psyml.path, "some-path/")
        self.assertEqual(psyml.region, "some-region")
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
