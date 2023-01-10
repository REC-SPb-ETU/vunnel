import datetime
import os
from dataclasses import dataclass, field

from vunnel import provider, result, schema

from .parser import Parser, ol_config


@dataclass
class Config:
    runtime: provider.RuntimeConfig = field(
        default_factory=lambda: provider.RuntimeConfig(
            result_store=result.StoreStrategy.SQLITE,
            existing_results=provider.ResultStatePolicy.DELETE_BEFORE_WRITE,
        )
    )
    request_timeout: int = 125


class Provider(provider.Provider):
    def __init__(self, root: str, config: Config):
        super().__init__(root, runtime_cfg=config.runtime)
        self.config = config

        self.logger.debug(f"config: {config}")

        self.schema = schema.OSSchema()
        self.parser = Parser(
            workspace=self.workspace,
            config=ol_config,
            download_timeout=self.config.request_timeout,
            logger=self.logger,
        )

    @classmethod
    def name(cls) -> str:
        return "oracle"

    def update(self, last_updated: datetime.datetime | None) -> tuple[list[str], int]:

        with self.results_writer() as writer:
            # TODO: tech debt: on subsequent runs, we should only write new vulns (this currently re-writes all)
            vuln_dict = self.parser.get(skip_if_exists=self.config.runtime.skip_if_exists)

            for (vuln_id, namespace), (_, record) in vuln_dict.items():
                namespace = namespace.lower()
                vuln_id = vuln_id.lower()
                writer.write(
                    identifier=os.path.join(namespace, vuln_id),
                    schema=self.schema,
                    payload=record,
                )

        return self.parser.urls, len(writer)