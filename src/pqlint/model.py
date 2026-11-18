from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator


class Origin(str, Enum):
    IAC = "iac"
    LIVE = "live"


class ExposureType(str, Enum):
    CONFIDENTIALITY = "confidentiality"
    AUTHENTICITY = "authenticity"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


# Explicit sentinel representation for unresolved attributes in offline IaC analysis
UNKNOWN: str = "<UNKNOWN>"


def is_unknown(val: Any) -> bool:
    """Check if an attribute value represents an unresolved offline value."""
    if val is None:
        return False
    if val is UNKNOWN:
        return True
    if isinstance(val, str):
        s = val.strip()
        if s in (UNKNOWN, "<UNKNOWN>", "UNKNOWN"):
            return True
        # Detect unexpanded Terraform syntax in string values
        if s.startswith("${") and s.endswith("}"):
            return True
        if (
            s.startswith("var.")
            or s.startswith("local.")
            or s.startswith("module.")
            or s.startswith("data.")
        ):
            return True
    return False


class Location(BaseModel):
    """Source code location for IaC resources."""

    file_path: str
    start_line: Optional[int] = None


class MoscaScore(BaseModel):
    """Structured Mosca inequality evaluation result."""

    x: Optional[int] = None
    y: int
    z: int
    at_risk: bool


class Resource(BaseModel):
    """Normalized resource model shared by IaC parsers and live collectors."""

    type: str
    name: str
    provider_id: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    location: Optional[Location] = None
    fingerprint: Optional[str] = None
    origin: Origin

    def __init__(
        self,
        type: str = "",
        name: str = "",
        provider_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        location: Optional[Location] = None,
        fingerprint: Optional[str] = None,
        origin: Origin = Origin.IAC,
        source_location: Optional[str] = None,
        **data: Any,
    ) -> None:
        if source_location is not None and location is None:
            if ":" in source_location:
                parts = source_location.rsplit(":", 1)
                if parts[1].isdigit():
                    location = Location(file_path=parts[0], start_line=int(parts[1]))
                else:
                    location = Location(file_path=source_location)
            else:
                location = Location(file_path=source_location)
        init_data: Dict[str, Any] = {
            "type": type,
            "name": name,
            "provider_id": provider_id,
            "attributes": attributes if attributes is not None else {},
            "location": location,
            "fingerprint": fingerprint,
            "origin": origin,
            **data,
        }
        super().__init__(**init_data)

    @model_validator(mode="before")
    @classmethod
    def _migrate_source_location(cls, data: Any) -> Any:
        if isinstance(data, dict) and "source_location" in data and "location" not in data:
            loc = data.pop("source_location")
            if loc:
                if isinstance(loc, str) and ":" in loc:
                    parts = loc.rsplit(":", 1)
                    if parts[1].isdigit():
                        data["location"] = Location(file_path=parts[0], start_line=int(parts[1]))
                    else:
                        data["location"] = Location(file_path=loc)
                elif isinstance(loc, str):
                    data["location"] = Location(file_path=loc)
                elif isinstance(loc, dict):
                    data["location"] = loc
        return data

    @property
    def source_location(self) -> Optional[str]:
        if self.location:
            if self.location.start_line is not None:
                return f"{self.location.file_path}:{self.location.start_line}"
            return self.location.file_path
        return None

    @source_location.setter
    def source_location(self, val: Optional[str]) -> None:
        if val is None:
            self.location = None
        elif ":" in val:
            parts = val.rsplit(":", 1)
            if parts[1].isdigit():
                self.location = Location(file_path=parts[0], start_line=int(parts[1]))
            else:
                self.location = Location(file_path=val)
        else:
            self.location = Location(file_path=val)


class Finding(BaseModel):
    """A single vulnerability or weakness detected by a rule."""

    rule_id: str
    rule_title: str
    resource: Resource
    severity: Severity
    exposure: ExposureType
    message: str
    remediation_ref: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    mosca: Optional[MoscaScore] = None


class ScanResult(BaseModel):
    """Top-level wrapper for all scan outputs to ensure comprehensive redaction."""

    schema_version: str = "1.0.0"
    resources: List[Resource] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    tool_version: str = "0.1.0"
    unresolved_count: int = 0
