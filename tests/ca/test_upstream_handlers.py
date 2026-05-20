"""Tests for upstream challenge handler factories."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest

from acmeeh.ca.base import CAError
from acmeeh.ca.upstream_handlers import (
    CallbackDnsFactory,
    CallbackHttpFactory,
    FileHttpFactory,
    UpstreamHandlerFactory,
    load_upstream_handler,
)


@pytest.fixture()
def mock_acmeow_handlers():
    """Temporarily inject a mock acmeow.handlers module into sys.modules."""
    mock_handlers = MagicMock()
    mock_acmeow = MagicMock()
    mock_acmeow.handlers = mock_handlers

    saved = {}
    for key in ("acmeow", "acmeow.handlers"):
        if key in sys.modules:
            saved[key] = sys.modules[key]

    sys.modules["acmeow"] = mock_acmeow
    sys.modules["acmeow.handlers"] = mock_handlers
    yield mock_handlers

    for key in ("acmeow", "acmeow.handlers"):
        if key in saved:
            sys.modules[key] = saved[key]
        else:
            sys.modules.pop(key, None)


class TestCallbackDnsFactory:
    @patch("acmeeh.ca.upstream_handlers.CallbackDnsFactory.create")
    def test_load_by_name(self, mock_create):
        mock_handler = MagicMock()
        mock_create.return_value = mock_handler
        config = {
            "create_script": "/usr/bin/dns-create.sh",
            "delete_script": "/usr/bin/dns-delete.sh",
            "propagation_delay": 30,
        }
        result = load_upstream_handler("callback_dns", config)
        assert result is mock_handler

    def test_missing_create_script_raises(self):
        factory = CallbackDnsFactory()
        with pytest.raises(CAError, match="create_script"):
            factory.create({"delete_script": "/usr/bin/dns-delete.sh"})

    def test_missing_delete_script_raises(self):
        factory = CallbackDnsFactory()
        with pytest.raises(CAError, match="delete_script"):
            factory.create({"create_script": "/usr/bin/dns-create.sh"})

    def test_creates_handler_with_callbacks(self, mock_acmeow_handlers):
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.CallbackDnsHandler = mock_handler_cls

        factory = CallbackDnsFactory()
        factory.create(
            {
                "create_script": "/usr/bin/dns-create.sh",
                "delete_script": "/usr/bin/dns-delete.sh",
                "propagation_delay": 20,
            }
        )
        mock_handler_cls.assert_called_once()
        kwargs = mock_handler_cls.call_args[1]
        assert kwargs["propagation_delay"] == 20
        assert callable(kwargs["create_record"])
        assert callable(kwargs["delete_record"])


class TestFileHttpFactory:
    def test_missing_webroot_raises(self):
        factory = FileHttpFactory()
        with pytest.raises(CAError, match="webroot"):
            factory.create({})

    def test_creates_handler(self, mock_acmeow_handlers):
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.FileHttpHandler = mock_handler_cls

        factory = FileHttpFactory()
        factory.create({"webroot": "/var/www/html"})
        mock_handler_cls.assert_called_once_with(webroot="/var/www/html")


class TestCallbackHttpFactory:
    def test_missing_deploy_script_raises(self):
        factory = CallbackHttpFactory()
        with pytest.raises(CAError, match="deploy_script"):
            factory.create({"cleanup_script": "/usr/bin/cleanup.sh"})

    def test_missing_cleanup_script_raises(self):
        factory = CallbackHttpFactory()
        with pytest.raises(CAError, match="cleanup_script"):
            factory.create({"deploy_script": "/usr/bin/deploy.sh"})

    def test_creates_handler(self, mock_acmeow_handlers):
        mock_handler_cls = MagicMock()
        mock_acmeow_handlers.CallbackHttpHandler = mock_handler_cls

        factory = CallbackHttpFactory()
        factory.create(
            {
                "deploy_script": "/usr/bin/deploy.sh",
                "cleanup_script": "/usr/bin/cleanup.sh",
            }
        )
        mock_handler_cls.assert_called_once()
        kwargs = mock_handler_cls.call_args[1]
        assert callable(kwargs["setup_callback"])
        assert callable(kwargs["cleanup_callback"])


class TestLoadUpstreamHandler:
    def test_unknown_handler_raises(self):
        with pytest.raises(CAError, match="Unknown upstream challenge handler"):
            load_upstream_handler("nonexistent", {})

    def test_ext_invalid_fqn_raises(self):
        with pytest.raises(CAError, match="must be fully qualified"):
            load_upstream_handler("ext:BadName", {})

    def test_ext_import_error_raises(self):
        with pytest.raises(CAError, match="Failed to load"):
            load_upstream_handler("ext:nonexistent.module.Factory", {})

    def test_ext_not_subclass_raises(self):
        with patch("acmeeh.ca.upstream_handlers.importlib.import_module") as mock_import:
            mock_module = MagicMock()
            mock_module.NotAFactory = str  # Not an UpstreamHandlerFactory
            mock_import.return_value = mock_module
            with pytest.raises(CAError, match="must be a subclass"):
                load_upstream_handler("ext:mypackage.module.NotAFactory", {})

    def test_ext_valid_factory(self):
        class MockFactory(UpstreamHandlerFactory):
            def create(self, config):
                return "mock-handler"

        with patch("acmeeh.ca.upstream_handlers.importlib.import_module") as mock_import:
            mock_module = MagicMock()
            mock_module.MockFactory = MockFactory
            mock_import.return_value = mock_module
            result = load_upstream_handler("ext:mypackage.module.MockFactory", {})
            assert result == "mock-handler"
