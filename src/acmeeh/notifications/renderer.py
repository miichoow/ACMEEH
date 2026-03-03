"""Jinja2 template renderer for notification emails.

Resolves templates with a two-tier loader:
1. User-specified ``templates_path`` (overrides)
2. Built-in templates shipped with the package
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from jinja2 import BaseLoader, ChoiceLoader, Environment, FileSystemLoader, PackageLoader

if TYPE_CHECKING:
    from acmeeh.core.types import NotificationType

log = logging.getLogger(__name__)


class TemplateRenderer:
    """Renders notification email subjects and bodies from Jinja2 templates."""

    def __init__(self, templates_path: str | None = None) -> None:
        loaders: list[BaseLoader] = []
        if templates_path:
            loaders.append(FileSystemLoader(templates_path))
        loaders.append(PackageLoader("acmeeh.notifications", "templates"))

        self._env = Environment(
            loader=ChoiceLoader(loaders),
            autoescape=True,
            keep_trailing_newline=False,
        )

    def render(
        self,
        notification_type: NotificationType,
        context: dict[str, Any],
    ) -> tuple[str, str]:
        """Render subject and body for a notification type.

        Parameters
        ----------
        notification_type:
            The type of notification to render.
        context:
            Template variables.

        Returns
        -------
        tuple[str, str]
            ``(subject, body_html)``

        """
        type_name = notification_type.value
        try:
            subject_tpl = self._env.get_template(f"{type_name}_subject.txt")
            body_tpl = self._env.get_template(f"{type_name}_body.html")

            subject = subject_tpl.render(**context).strip()
            body = body_tpl.render(**context)
        except Exception as exc:
            log.warning("Failed to render notification template '%s': %s", type_name, exc)
            raise

        return subject, body
