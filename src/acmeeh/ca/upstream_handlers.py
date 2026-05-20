"""Upstream ACME challenge handler bridge.

Provide a factory abstraction for creating ACMEOW
:class:`ChallengeHandler` instances from JSON configuration.

Built-in factories:

- ``callback_dns``  -- wrap shell scripts for DNS-01 record management
- ``file_http``     -- serve HTTP-01 tokens from a webroot directory
- ``callback_http`` -- wrap shell scripts for HTTP-01 token management

Custom factories can be loaded via the ``ext:`` prefix
(e.g. ``ext:mypackage.handlers.MyFactory``).
"""

from __future__ import annotations

import abc
import importlib
import logging
import subprocess
from typing import Any

from acmeeh.ca.base import CAError

log = logging.getLogger(__name__)


class UpstreamHandlerFactory(abc.ABC):
    """Create an ACMEOW ChallengeHandler from JSON config."""

    @abc.abstractmethod
    def create(self, config: dict[str, Any]) -> Any:
        """Build and return a ChallengeHandler instance.

        Parameters
        ----------
        config:
            The ``challenge_handler_config`` dict from settings.

        Returns
        -------
        acmeow.ChallengeHandler
            A ready-to-use challenge handler.

        """


class CallbackDnsFactory(UpstreamHandlerFactory):
    """Factory for ACMEOW's CallbackDnsHandler.

    Required config keys:

    - ``create_script``: path to script called as
      ``script <domain> <record_name> <record_value>``
    - ``delete_script``: path to script called as
      ``script <domain> <record_name>``
    - ``propagation_delay``: seconds to wait after record
      creation (default: 10)

    """

    def create(self, config: dict[str, Any]) -> Any:
        """Build a CallbackDnsHandler from the given config."""
        create_script = config.get("create_script")
        delete_script = config.get("delete_script")
        if not create_script:
            msg = "callback_dns handler requires 'create_script' in config"
            raise CAError(msg)
        if not delete_script:
            msg = "callback_dns handler requires 'delete_script' in config"
            raise CAError(msg)

        from acmeow.handlers import CallbackDnsHandler  # noqa: PLC0415

        propagation_delay = config.get("propagation_delay", 10)  # noqa: PLR2004
        script_timeout = config.get("script_timeout", 60)  # noqa: PLR2004

        def create_record(
            domain: str,
            record_name: str,
            record_value: str,
        ) -> None:
            log.info(
                "DNS create: %s %s via %s",
                record_name,
                domain,
                create_script,
            )
            subprocess.run(  # noqa: S603
                [create_script, domain, record_name, record_value],
                check=True,
                timeout=script_timeout,
                capture_output=True,
                text=True,
            )

        def delete_record(
            domain: str,
            record_name: str,
        ) -> None:
            log.info(
                "DNS delete: %s %s via %s",
                record_name,
                domain,
                delete_script,
            )
            subprocess.run(  # noqa: S603
                [delete_script, domain, record_name],
                check=True,
                timeout=script_timeout,
                capture_output=True,
                text=True,
            )

        return CallbackDnsHandler(
            create_record=create_record,
            delete_record=delete_record,
            propagation_delay=propagation_delay,
        )


class FileHttpFactory(UpstreamHandlerFactory):
    """Factory for ACMEOW's FileHttpHandler.

    Required config keys:

    - ``webroot``: path to the webroot directory for
      ``.well-known/acme-challenge/``

    """

    def create(self, config: dict[str, Any]) -> Any:
        """Build a FileHttpHandler from the given config."""
        webroot = config.get("webroot")
        if not webroot:
            msg = "file_http handler requires 'webroot' in config"
            raise CAError(msg)

        from acmeow.handlers import FileHttpHandler  # noqa: PLC0415

        return FileHttpHandler(webroot=webroot)


class CallbackHttpFactory(UpstreamHandlerFactory):
    """Factory for ACMEOW's CallbackHttpHandler.

    Required config keys:

    - ``deploy_script``: path to script called as
      ``script <domain> <token> <key_authorization>``
    - ``cleanup_script``: path to script called as
      ``script <domain> <token>``

    """

    def create(self, config: dict[str, Any]) -> Any:
        """Build a CallbackHttpHandler from the given config."""
        deploy_script = config.get("deploy_script")
        cleanup_script = config.get("cleanup_script")
        if not deploy_script:
            msg = "callback_http handler requires 'deploy_script' in config"
            raise CAError(msg)
        if not cleanup_script:
            msg = "callback_http handler requires 'cleanup_script' in config"
            raise CAError(msg)

        from acmeow.handlers import CallbackHttpHandler  # noqa: PLC0415

        script_timeout = config.get("script_timeout", 60)  # noqa: PLR2004

        def deploy(
            domain: str,
            token: str,
            key_authorization: str,
        ) -> None:
            log.info(
                "HTTP deploy: %s %s via %s",
                token,
                domain,
                deploy_script,
            )
            subprocess.run(  # noqa: S603
                [deploy_script, domain, token, key_authorization],
                check=True,
                timeout=script_timeout,
                capture_output=True,
                text=True,
            )

        def cleanup(domain: str, token: str) -> None:
            log.info(
                "HTTP cleanup: %s %s via %s",
                token,
                domain,
                cleanup_script,
            )
            subprocess.run(  # noqa: S603
                [cleanup_script, domain, token],
                check=True,
                timeout=script_timeout,
                capture_output=True,
                text=True,
            )

        return CallbackHttpHandler(
            setup_callback=deploy,
            cleanup_callback=cleanup,
        )


_BUILTIN_FACTORIES: dict[str, UpstreamHandlerFactory] = {
    "callback_dns": CallbackDnsFactory(),
    "file_http": FileHttpFactory(),
    "callback_http": CallbackHttpFactory(),
}


def load_upstream_handler(  # noqa: PLR0912
    handler_name: str,
    config: dict[str, Any],
) -> Any:
    """Load and create an upstream challenge handler.

    Parameters
    ----------
    handler_name:
        Built-in name (``callback_dns``, ``file_http``,
        ``callback_http``) or ``ext:fully.qualified.FactoryClass``
        for custom factories.
    config:
        The ``challenge_handler_config`` dict from settings.

    Returns
    -------
    acmeow.ChallengeHandler
        A ready-to-use challenge handler instance.

    Raises
    ------
    CAError
        If the handler cannot be loaded or created.

    """
    if handler_name in _BUILTIN_FACTORIES:
        return _BUILTIN_FACTORIES[handler_name].create(config)

    if handler_name.startswith("ext:"):
        return _load_external_handler(handler_name[4:], config)

    msg = (
        f"Unknown upstream challenge handler '{handler_name}'; "
        f"built-in options: {sorted(_BUILTIN_FACTORIES)}. "
        "Use 'ext:mypackage.module.FactoryClass' for custom handlers."
    )
    raise CAError(msg)


def _load_external_handler(
    fqn: str,
    config: dict[str, Any],
) -> Any:
    """Load and instantiate an external handler factory by FQN.

    Parameters
    ----------
    fqn:
        Fully-qualified class name (e.g. ``mypackage.module.Class``).
    config:
        The ``challenge_handler_config`` dict from settings.

    Returns
    -------
    acmeow.ChallengeHandler
        A ready-to-use challenge handler instance.

    Raises
    ------
    CAError
        If the factory class cannot be loaded or is not a valid subclass.

    """
    module_path, _, cls_name = fqn.rpartition(".")
    if not module_path:
        msg = (
            f"Invalid external handler factory '{fqn}': must be "
            "fully qualified (e.g. 'mypackage.module.FactoryClass')"
        )
        raise CAError(msg)
    try:
        module = importlib.import_module(module_path)
        cls = getattr(module, cls_name)
    except (ImportError, AttributeError) as exc:
        msg = f"Failed to load external handler factory '{fqn}': {exc}"
        raise CAError(msg) from exc

    if not (isinstance(cls, type) and issubclass(cls, UpstreamHandlerFactory)):
        msg = f"External handler factory '{fqn}' must be a subclass of UpstreamHandlerFactory"
        raise CAError(msg)

    factory = cls()
    return factory.create(config)
