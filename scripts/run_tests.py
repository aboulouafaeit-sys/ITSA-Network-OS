#!/usr/bin/env python3
"""Standalone test runner for ITSA Network OS using Python's standard unittest library."""

import sys
import unittest
from pathlib import Path

# Ensure 'src' is on sys.path for test execution
ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
TESTS_DIR = ROOT_DIR / "tests"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def run_all_tests() -> int:
    """Discover and execute all unit and integration tests."""
    print("=" * 60)
    print(" Running ITSA Network OS Automated Test Suite")
    print("=" * 60)
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(TESTS_DIR), pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("\n" + "=" * 60)
    if result.wasSuccessful():
        print(f" ALL {result.testsRun} TESTS PASSED SUCCESSFULLY!")
        print("=" * 60)
        return 0
    else:
        print(f" TESTS FAILED: {len(result.failures)} failures, {len(result.errors)} errors")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(run_all_tests())
