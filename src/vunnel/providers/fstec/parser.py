from __future__ import annotations

import io
import logging
import os
from zipfile import ZipFile

import defusedxml.ElementTree as ET
import requests

from vunnel import utils, workspace

NAMESPACE = "debian:distro:debian:10"  # github:language:java"#debian:language:java"  # github, схема


class Parser:
    _zip_url_ = "https://bdu.fstec.ru/files/documents/vulxml.zip"
    _vulxml_file_ = "export/export.xml"

    def __init__(self, ws: workspace.Workspace, download_timeout: int = 125, logger: logging.Logger | None = None):
        self.workspace = ws
        self.download_timeout = download_timeout
        self.xml_file_path = os.path.join(ws.input_path, self._vulxml_file_)

        self.urls = [self._zip_url_]

        if not logger:
            logger = logging.getLogger(self.__class__.__name__)
        self.logger = logger

    def get(self):
        self._download()
        yield from self._normalize()

    @utils.retry_with_backoff()
    def _download(self):
        self.logger.info(f"downloading vulnerability data from {self._zip_url_}")

        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"}

        r = requests.get(
            url=self._zip_url_,
            timeout=self.download_timeout,
            headers=headers,
            verify=False,
        )
        r.raise_for_status()

        with ZipFile(io.BytesIO(r.content), "r") as zip_ref:
            bad_file = zip_ref.testzip()
            if bad_file:
                raise ValueError(f"File {bad_file} is broken")
            if self._vulxml_file_ not in zip_ref.namelist():
                raise ValueError(f"Unexpected namelist: {zip_ref.namelist()}")
            zip_ref.extract(self._vulxml_file_, self.workspace.input_path)

    def _parse_severity(self, xml_text: str):
        """
        Details at https://bdu.fstec.ru/ubi/terms/terms/view/id/56
        """
        text = xml_text.lower()
        if "критический" in text:
            return "Critical"
        if "высокий" in text:
            return "High"
        if "средний" in text:
            return "Medium"
        if "нижний" in text:
            return "Low"
        return "Unknown"

    def _process_definition(self, vuln_xml, vuln_dict):
        vuln_dict["identifier"] = vuln_xml.find("identifier").text
        vuln_dict["name"] = vuln_xml.find("name").text
        vuln_dict["description"] = vuln_xml.find("description").text
        vuln_dict["severity"] = self._parse_severity(vuln_xml.find("severity").text)

    def _normalize(self):

        vuln_dict = {}
        processing = None

        for event, xml_element in ET.iterparse(self.xml_file_path, events=("start", "end")):
            if event == "start":
                if xml_element.tag == "vul":
                    processing = True
                    vuln_dict.clear()
            elif processing and xml_element.tag == "vul" and event == "end":
                try:
                    self._process_definition(xml_element, vuln_dict)
                except:
                    self.logger.exception("Error parsing oval record. Logging error and continuing")
                else:
                    # NOTE: this is in the data shape described by the OS vulnerability schema
                    _id, _vuln = vuln_dict["identifier"], {
                        "Vulnerability": {
                            "Name": vuln_dict["identifier"],
                            "NamespaceName": NAMESPACE,
                            "Link": f"https://bdu.fstec.ru/vul/{vuln_dict['identifier'][len('BDU:'):]}",
                            "Severity": self._parse_severity(vuln_dict["severity"]),
                            "Description": vuln_dict["description"],
                            "FixedIn": [
                                {
                                    "Name": "Log4j",
                                    "VersionFormat": "jar",
                                    "NamespaceName": NAMESPACE,
                                    "Version": "None",
                                }
                                # for p in []
                            ],
                        },
                    }
                    yield _id, _vuln
                finally:
                    processing = False

            # clear the element if it doesn't need to be processed or done processing
            if not processing and event == "end":
                xml_element.clear()
