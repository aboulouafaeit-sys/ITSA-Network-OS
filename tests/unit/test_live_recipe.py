"""Unit tests verifying the integrity of the Debian Live Build recipe files."""

import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DEBIAN_LIVE_DIR = ROOT_DIR / "debian-live"


class TestLiveBuildRecipe(unittest.TestCase):
    """Validate structure, syntax, and presence of live-build artifacts."""

    def test_auto_config_exists_and_configured(self) -> None:
        cfg_file = DEBIAN_LIVE_DIR / "auto" / "config"
        self.assertTrue(cfg_file.is_file(), "debian-live/auto/config must exist")
        content = cfg_file.read_text(encoding="utf-8")
        self.assertIn("--distribution trixie", content)
        self.assertIn("--architectures amd64", content)
        self.assertIn("itsa-network-os", content)

    def test_package_list_contains_essential_tools(self) -> None:
        pkg_file = DEBIAN_LIVE_DIR / "config" / "package-lists" / "itsa.list.chroot"
        self.assertTrue(pkg_file.is_file(), "package-lists/itsa.list.chroot must exist")
        content = pkg_file.read_text(encoding="utf-8")
        required_pkgs = ["python3", "python3-venv", "xfce4", "live-boot", "iproute2", "tcpdump"]
        for pkg in required_pkgs:
            self.assertIn(pkg, content, f"Package '{pkg}' missing from package list")

    def test_desktop_entry_validity(self) -> None:
        desktop_file = (
            DEBIAN_LIVE_DIR / "config" / "includes.chroot" / "usr" / "share" / "applications" / "itsa-network-os.desktop"
        )
        self.assertTrue(desktop_file.is_file(), "Desktop launcher file must exist")
        content = desktop_file.read_text(encoding="utf-8")
        self.assertIn("[Desktop Entry]", content)
        self.assertIn("Name=ITSA Network OS", content)
        self.assertIn("Exec=/usr/local/bin/itsa-network-os --gui", content)

    def test_chroot_hook_integrity(self) -> None:
        hook_file = DEBIAN_LIVE_DIR / "config" / "hooks" / "live" / "01-install-itsa.hook.chroot"
        self.assertTrue(hook_file.is_file(), "01-install-itsa.hook.chroot must exist")
        content = hook_file.read_text(encoding="utf-8")
        self.assertIn("/opt/itsa-network-os", content)
        self.assertIn("/usr/local/bin/itsa-network-os", content)

    def test_build_script_has_safety_checks(self) -> None:
        build_script = ROOT_DIR / "scripts" / "build_live_iso.sh"
        self.assertTrue(build_script.is_file(), "scripts/build_live_iso.sh must exist")
        content = build_script.read_text(encoding="utf-8")
        self.assertIn("id -u", content, "Build script must check for root/privilege safety")
        self.assertIn("FREE_GB", content, "Build script must verify free disk space")


if __name__ == "__main__":
    unittest.main()
