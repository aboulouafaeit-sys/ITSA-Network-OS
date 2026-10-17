"""Unit tests for configuration manager."""

import unittest
from pathlib import Path
from itsa_network_os.core.config import AppConfig, get_default_config, load_config


class TestAppConfig(unittest.TestCase):
    """Test safe defaults and immutability of configuration."""

    def test_default_config_properties(self) -> None:
        config = get_default_config()
        self.assertEqual(config.app_name, "ITSA Network OS")
        self.assertTrue(config.offline_mode)
        self.assertFalse(config.enable_telemetry)
        self.assertTrue(config.use_mock_network)

    def test_immutability(self) -> None:
        config = get_default_config()
        with self.assertRaises(Exception):
            config.enable_telemetry = True  # type: ignore

    def test_load_non_existent_config(self) -> None:
        fake_path = Path("/non/existent/path/config.json")
        config = load_config(fake_path)
        self.assertIsInstance(config, AppConfig)
        self.assertFalse(config.enable_telemetry)


if __name__ == "__main__":
    unittest.main()
