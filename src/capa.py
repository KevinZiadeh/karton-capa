"""Karton CAPA Service."""

import json
import subprocess
from typing import Any, ClassVar, cast

from karton.core import Karton, RemoteResource, Task

from .__version__ import __version__


class Capa(Karton):
    """
    Perform CAPA on samples.

    **Consumes:**
    ```
    {"type": "sample", "stage": "recognized"}
    ```

    **Produces:**
    ```
    {
        "headers": {"type": "sample", "stage": "analyzed"},
        "payload": {
            "sample": sample,
            "tags": <Mitre TTP tags>,
            "attributes": {
                "capa": <Minimized CAPA result>
            }
        }
    }
    ```
    """

    identity = "karton.capa"
    filters: ClassVar = [
        {"type": "sample", "stage": "recognized"},
    ]
    version = __version__


    WANTED_META_KEYS = (
        "name",
        "namespace",
        "attack",
        "mbc",
        "description",
        "lib",
        "is_subscope_rule",
        "maec",
    )


    @staticmethod
    def normalize(name: str) -> str:
        """
        Normalize the given string.

        Args:
            name (str): string to normalize

        Returns:
            str: normalized string

        """
        return name.lower().replace(" ", "-")

    @staticmethod
    def get_tags(capa_data: dict[str, dict[str, Any]]) -> list[str]:
        """
        Parse output from CAPA data and generate tags.

        Args:
            capa_data (dict[str, dict[str, Any]]): parsed CAPA output

        Returns:
            list(str): list of tags to add to the sample

        """
        if not capa_data:
            return []

        tags = set()

        for rule_data in capa_data.values():
            for ttp in rule_data.get("attack", []):
                tags.add(Capa.normalize(ttp["id"]))
            # Too noisy
            # for mbc in rule_data.get("mbc", []):
            #     tags.add(f"mbc:{Capa.normalize(mbc["id"])}")  # noqa: ERA001

        return list(tags)

    def reduce_rules_meta(self, doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """
        Extract only wanted keys from rules object.

        Given a dict `doc` with a 'rules' mapping, return a new dict { rule_key: reduced_meta } where
        `reduced_meta` contains only the keys listed in `WANTED_META_KEYS`. Missing keys are set to None

        Args:
            doc (dict[str, Any]): complete CAPA output

        Returns:
            list(str): list of tags to add to the sample

        """
        out: dict[str, dict[str, Any]] = {}
        rules = doc.get("rules", {})
        for rule_key, rule_value in rules.items():
            meta = rule_value.get("meta", {})
            reduced_meta: dict[str, Any] = {}
            for k in self.WANTED_META_KEYS:
                reduced_meta[k] = meta.get(k, None)
            out[rule_key] = reduced_meta
        return out

    def process(self, task: Task) -> None:
        """
        Entry point of this service.

        Takes a sample and perform CAPA on it. Pass all relevant data to next task.

        Args:
            task (Task): Karton task

        """
        sample_resource = cast("RemoteResource", task.get_resource("sample"))

        capa_data = None
        with sample_resource.download_temporary_file() as f:
            capa_data = subprocess.check_output([
                "/app/.venv/bin/capa",
                "--json",
                "-r",
                "/app/rules",
                "-s",
                "/capa/sigs",
                f.name,
            ])
            capa_data = capa_data.decode("utf-8")

        if not capa_data:
            return

        self.log.info(f"Successfully perform CAPA on {sample_resource.sha256}")

        capa_json = json.loads(capa_data)
        reduced_data = self.reduce_rules_meta(capa_json)

        tags = Capa.get_tags(reduced_data)
        self.send_task(
            Task(
                headers={"type": "sample", "stage": "analyzed"},
                payload={
                    "sample": sample_resource,
                    "tags": tags,
                    "attributes": {
                        "capa": list(reduced_data.values()),
                    },
                },
            ),
        )
        self.log.info(f"Successfully pushed CAPA data for {sample_resource.sha256}")
