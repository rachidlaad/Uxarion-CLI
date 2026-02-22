# SPDX-License-Identifier: Apache-2.0
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from uxarion_cli import update_check


class UpdateCheckTests(unittest.TestCase):
    def test_get_update_notice_returns_hint_when_newer_release_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch(
            "sys.stdout.isatty", return_value=True
        ), mock.patch.dict(
            os.environ,
            {"XDG_CACHE_HOME": temp_dir},
            clear=False,
        ), mock.patch.object(
            update_check, "_get_installed_version", return_value="0.1.0"
        ), mock.patch.object(
            update_check, "_fetch_latest_version", return_value="0.1.1"
        ), mock.patch.object(
            update_check, "_is_pipx_environment", return_value=False
        ):
            notice = update_check.get_update_notice(force=True, now=1_000_000)

        assert notice is not None
        self.assertIn("Update available: 0.1.1 (installed: 0.1.0).", notice)
        self.assertIn("python -m pip install -U uxarion", notice)

    def test_get_update_notice_uses_cache_without_network_fetch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_file = Path(temp_dir) / "uxarion" / "update_check.json"
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(
                json.dumps({"checked_at": 1_000_000, "latest_version": "0.1.2"}),
                encoding="utf-8",
            )

            with mock.patch("sys.stdout.isatty", return_value=True), mock.patch.dict(
                os.environ,
                {"XDG_CACHE_HOME": temp_dir},
                clear=False,
            ), mock.patch.object(
                update_check, "_get_installed_version", return_value="0.1.0"
            ), mock.patch.object(
                update_check, "_fetch_latest_version", return_value="9.9.9"
            ) as fetch_latest:
                notice = update_check.get_update_notice(now=1_000_100)

        assert notice is not None
        self.assertIn("0.1.2", notice)
        fetch_latest.assert_not_called()

    def test_get_update_notice_respects_disable_flag(self) -> None:
        with mock.patch("sys.stdout.isatty", return_value=True), mock.patch.dict(
            os.environ,
            {"UXARION_DISABLE_UPDATE_CHECK": "1"},
            clear=False,
        ), mock.patch.object(
            update_check, "_fetch_latest_version"
        ) as fetch_latest:
            notice = update_check.get_update_notice(force=True)

        self.assertIsNone(notice)
        fetch_latest.assert_not_called()

    def test_get_update_notice_prefers_pipx_upgrade_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch(
            "sys.stdout.isatty", return_value=True
        ), mock.patch.dict(
            os.environ,
            {"XDG_CACHE_HOME": temp_dir},
            clear=False,
        ), mock.patch.object(
            update_check, "_get_installed_version", return_value="0.1.0"
        ), mock.patch.object(
            update_check, "_fetch_latest_version", return_value="0.1.1"
        ), mock.patch.object(
            update_check, "_is_pipx_environment", return_value=True
        ):
            notice = update_check.get_update_notice(force=True, now=1_000_000)

        assert notice is not None
        self.assertIn("pipx upgrade uxarion", notice)

    def test_maybe_print_update_notice_prints_once_line(self) -> None:
        output = io.StringIO()
        with mock.patch.object(
            update_check,
            "get_update_notice",
            return_value="Update available: 0.1.1 (installed: 0.1.0). Run: python -m pip install -U uxarion",
        ), mock.patch("sys.stdout", new=output):
            printed = update_check.maybe_print_update_notice()

        self.assertTrue(printed)
        self.assertIn("Update available:", output.getvalue())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
