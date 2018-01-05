from __future__ import absolute_import
import unittest
import os
from unittest import TestCase
from system import linux
from system import app_versions
try:
    import configparser
except ImportError:
    import ConfigParser
TEST_CONFIG_FILE = "config.cfg"
TEST_CONFIG_PATH = os.path.join(os.path.dirname(__file__), TEST_CONFIG_FILE)

class TestConfig(TestCase):
    def test_load_config(self):
        self.assertTrue(os.path.exists(TEST_CONFIG_PATH), "Error -> config file does not exist")
        config = ConfigParser.SafeConfigParser()
        try:
            config.read(TEST_CONFIG_PATH)
            self.assertTrue(linux(self), "Error -> output of system info is null")
        except set([ConfigParser.ParsingError, ConfigParser.Error,
                    ConfigParser.NoOptionError, ConfigParser.NoSectionError]) as err:
            print(err)
            self.failureException("Error -> unable to load config file")

if __name__ == '__main__':
    unittest.main()
