"""Intel CSAF collector."""

from findupdates.collectors.intel.collector import IntelCollector
from findupdates.collectors.intel.csaf import PARSER_VERSION, parse_csaf_document

__all__ = ["PARSER_VERSION", "IntelCollector", "parse_csaf_document"]
