from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from vunnel import provider, result, schema

from .parser import Parser

if TYPE_CHECKING:
    import datetime

PROVIDER_NAME = "fstec"

SCHEMA = schema.OSSchema()


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_input=provider.InputStatePolicy.KEEP,
            existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE,
            on_error=provider.OnErrorConfig(
                action=provider.OnErrorAction.RETRY,
                input=provider.InputStatePolicy.DELETE,
                results=provider.ResultStatePolicy.DELETE,
            ),
        ),
    )
    request_timeout: int = 125


class Provider(provider.Provider):

    __schema__ = SCHEMA
    __distribution_version__ = int(__schema__.major_version)

    def __init__(self, root: str, config: Config | None = None):
        if not config:
            config = Config()

        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config
        self.logger.debug(f"config: {config}")

        self.parser = Parser(
            ws=self.workspace,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return PROVIDER_NAME

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:
        with self.results_writer() as writer:
            for vuln_id, record in self.parser.get():
                vuln_id = vuln_id.lower()

                writer.write(
                    identifier=vuln_id,
                    schema=SCHEMA,
                    payload=record,
                )

        return self.parser.urls, len(writer)
