"""Unit tests for acmeeh.db.init — database initialisation."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_db_settings(
    host="localhost",
    port=5432,
    database="acmeeh_test",
    user="testuser",
    password="secret",
    sslmode="prefer",
    min_connections=1,
    max_connections=10,
    connection_timeout=5.0,
    auto_setup=True,
    max_idle_seconds=300.0,
):
    return SimpleNamespace(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
        sslmode=sslmode,
        min_connections=min_connections,
        max_connections=max_connections,
        connection_timeout=connection_timeout,
        auto_setup=auto_setup,
        max_idle_seconds=max_idle_seconds,
    )


# ---------------------------------------------------------------------------
# _settings_to_config
# ---------------------------------------------------------------------------


class TestSettingsToConfig:
    @patch("acmeeh.db.init.DatabaseConfig")
    def test_maps_all_fields_correctly(self, mock_db_config_class):
        from acmeeh.db.init import _settings_to_config

        settings = _make_db_settings(
            host="db.example.com",
            port=5433,
            database="mydb",
            user="admin",
            password="pw123",
            sslmode="require",
            min_connections=2,
            max_connections=20,
            connection_timeout=10.0,
        )

        _settings_to_config(settings)

        mock_db_config_class.assert_called_once_with(
            host="db.example.com",
            port=5433,
            database="mydb",
            user="admin",
            password="pw123",
            sslmode="require",
            min_connections=2,
            max_connections=20,
            connection_timeout=10.0,
            max_idle_time=300.0,
            options={"prepare_threshold": None},
        )

    @patch("acmeeh.db.init.DatabaseConfig")
    def test_maps_default_fields(self, mock_db_config_class):
        from acmeeh.db.init import _settings_to_config

        settings = _make_db_settings()
        _settings_to_config(settings)

        mock_db_config_class.assert_called_once_with(
            host="localhost",
            port=5432,
            database="acmeeh_test",
            user="testuser",
            password="secret",
            sslmode="prefer",
            min_connections=1,
            max_connections=10,
            connection_timeout=5.0,
            max_idle_time=300.0,
            options={"prepare_threshold": None},
        )


# ---------------------------------------------------------------------------
# init_database — already initialised
# ---------------------------------------------------------------------------


class TestInitDatabaseAlreadyInitialized:
    @patch("acmeeh.db.init.Database")
    def test_returns_existing_when_already_initialized(self, mock_db_class):
        from acmeeh.db.init import init_database

        mock_instance = MagicMock()
        mock_db_class.is_initialized.return_value = True
        mock_db_class.get_instance.return_value = mock_instance

        settings = _make_db_settings()
        result = init_database(settings)

        assert result is mock_instance
        mock_db_class.is_initialized.assert_called_once()
        mock_db_class.get_instance.assert_called_once()
        mock_db_class.init.assert_not_called()


# ---------------------------------------------------------------------------
# init_database — new instance
# ---------------------------------------------------------------------------


class TestInitDatabaseNew:
    @patch("acmeeh.db.init._settings_to_config")
    @patch("acmeeh.db.init.Database")
    def test_creates_new_database_instance_with_auto_setup(
        self, mock_db_class, mock_settings_to_config
    ):
        from acmeeh.db.init import _SCHEMA_PATH, init_database

        mock_db_class.is_initialized.return_value = False
        mock_config = MagicMock()
        mock_settings_to_config.return_value = mock_config
        mock_instance = MagicMock()
        mock_db_class.init.return_value = mock_instance

        settings = _make_db_settings(auto_setup=True)
        result = init_database(settings)

        assert result is mock_instance
        mock_settings_to_config.assert_called_once_with(settings)
        mock_db_class.init.assert_called_once_with(
            config=mock_config,
            schema_path=_SCHEMA_PATH,
            auto_setup=True,
            interactive=False,
        )

    @patch("acmeeh.db.init._settings_to_config")
    @patch("acmeeh.db.init.Database")
    def test_creates_new_database_instance_without_auto_setup(
        self, mock_db_class, mock_settings_to_config
    ):
        from acmeeh.db.init import init_database

        mock_db_class.is_initialized.return_value = False
        mock_config = MagicMock()
        mock_settings_to_config.return_value = mock_config
        mock_instance = MagicMock()
        mock_db_class.init.return_value = mock_instance

        settings = _make_db_settings(auto_setup=False)
        result = init_database(settings)

        assert result is mock_instance
        mock_db_class.init.assert_called_once_with(
            config=mock_config,
            schema_path=None,
            auto_setup=False,
            interactive=False,
        )
