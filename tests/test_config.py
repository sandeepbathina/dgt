from __future__ import absolute_import
import unittest
import os
from unittest import TestCase
import ast
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
            self.assertIs(config.getboolean("logging", "enable"), True, "Error -> logging should be enabled")
            self.assertIs(config.getboolean("host", "enable"), True, "Error -> host info is not enabled")
            self.assertIs(config.getboolean("versions", "enable"), True, "Error -> versions check"
                                                                                    " is not enabled")
            self.assertIs(config.getboolean("system", "enable"), True, "Error -> system metrics"
                                                                                   " is not enabled")
            self.assertIs(config.getboolean("health", "enable"), True, "Error -> health of app is not enabled")
            self.assertIs(config.getboolean("docker", "enable"), True, "Error -> Docker metrics should"
                                                                              " be enabled")
            self.assertIs(config.getboolean("cert", "enable"), False, "Error -> Cert checks should"
                                                                         " be disabled")
            self.assertIsNotNone(config.get("logging", "path"), "Error -> log file path cannot"
                                                                              " be null")
            self.assertTrue(config.get("logging", "level").isupper(), "Error -> Log Level should be in uppercase ")
            self.assertIsInstance(ast.literal_eval(config.get("versions", "versions_for")), list, "Error -> Type should be list ")
            self.assertIsInstance(ast.literal_eval(config.get("health", "ports")), dict, "Error -> Type should be dict")
            self.assertEqual(len(ast.literal_eval(config.get("health", "application"))), len(ast.literal_eval(config.get("health", "logfile"))), "Error -> length of two list must be equal ")
            self.assertIsInstance(ast.literal_eval(config.get("health", "counter")), int, "Error -> Type must be integer" )

        except set([ConfigParser.ParsingError, ConfigParser.Error,
                    ConfigParser.NoOptionError, ConfigParser.NoSectionError]) as err:
            print(err)
            self.failureException("Error -> unable to load config file")
if __name__ == '__main__':
    unittest.main()
