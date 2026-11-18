"""Rule engine for evaluating declarative YAML rules against normalized resources."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

from pqlint.model import UNKNOWN, ExposureType, Finding, Resource, Severity, is_unknown
from pqlint.parsers.defaults import apply_provider_defaults

# Default path to declarative YAML rules
DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "data" / "rules"


def parse_rule_yaml(content: str) -> Dict[str, Any]:
    """Parse YAML string using PyYAML exclusively."""
    parsed = yaml.safe_load(content)
    return parsed if isinstance(parsed, dict) else {}


def load_rule_from_file(file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
    """Load a single declarative YAML rule definition from a file."""
    path = Path(file_path)
    if not path.is_file():
        return None

    try:
        content = path.read_text(encoding="utf-8")
        rule_data = parse_rule_yaml(content)
        if isinstance(rule_data, dict) and "id" in rule_data and "resource_type" in rule_data:
            return rule_data
    except Exception:
        return None
    return None


def load_rules_from_dir(rules_dir: Union[str, Path] = DEFAULT_RULES_DIR) -> List[Dict[str, Any]]:
    """
    Load all declarative YAML rules from a directory.
    Sorts rules by id for deterministic evaluation.
    """
    path = Path(rules_dir)
    if not path.exists() or not path.is_dir():
        return []

    rules: List[Dict[str, Any]] = []
    # Support both .yaml and .yml files
    rule_files = sorted(list(path.glob("*.yaml")) + list(path.glob("*.yml")))

    for file_path in rule_files:
        rule = load_rule_from_file(file_path)
        if rule:
            rules.append(rule)

    # Deduplicate by rule ID
    seen_ids = set()
    unique_rules: List[Dict[str, Any]] = []
    for r in rules:
        rid = str(r.get("id", ""))
        if rid and rid not in seen_ids:
            seen_ids.add(rid)
            unique_rules.append(r)

    # Sort deterministically by rule ID
    unique_rules.sort(key=lambda r: str(r.get("id", "")))
    return unique_rules


def extract_attribute_value(attributes: Dict[str, Any], path: str) -> Any:
    """Extract an attribute value, supporting direct keys and dot-separated nested paths."""
    if not path or not isinstance(attributes, dict):
        return None

    if path in attributes:
        val = attributes[path]
        if isinstance(val, list) and len(val) == 1 and not isinstance(val[0], (dict, list)):
            return val[0]
        return val

    parts = path.split(".")
    curr: Any = attributes
    for part in parts:
        if isinstance(curr, dict):
            if part in curr:
                curr = curr[part]
            else:
                return None
        elif isinstance(curr, list):
            found = False
            for item in curr:
                if isinstance(item, dict) and part in item:
                    curr = item[part]
                    found = True
                    break
            if not found:
                return None
        else:
            return None

    if isinstance(curr, list) and len(curr) == 1 and not isinstance(curr[0], (dict, list)):
        return curr[0]

    return curr


def evaluate_condition(
    condition: Dict[str, Any], attributes: Dict[str, Any]
) -> Tuple[Optional[bool], Any]:
    """
    Evaluate a rule's condition against resource attributes.

    Returns:
        (is_matched, evaluated_value)
        - is_matched: True if matched, False if not matched, None if UNKNOWN (unresolvable).
    """
    attribute_name = condition.get("attribute")
    if not attribute_name:
        return False, None

    actual_value = extract_attribute_value(attributes, attribute_name)

    # Explicit UNKNOWN resolution check: cannot evaluate condition offline
    if is_unknown(actual_value):
        return None, actual_value

    # Operator: 'in' (list membership)
    if "in" in condition:
        allowed = condition["in"]
        if isinstance(allowed, list):
            # Check exact match or string representation match
            allowed_str = [str(x) for x in allowed]
            if actual_value is not None:
                if actual_value in allowed or str(actual_value) in allowed_str:
                    return True, actual_value
        return False, actual_value

    # Operator: 'exists'
    if "exists" in condition:
        target_exists = bool(condition["exists"])
        if target_exists:
            return actual_value is not None, actual_value
        return actual_value is None, actual_value

    # Operator: 'equals' / 'eq'
    if "equals" in condition or "eq" in condition:
        target = condition.get("equals", condition.get("eq"))
        if actual_value == target or (
            actual_value is not None and str(actual_value) == str(target)
        ):
            return True, actual_value
        return False, actual_value

    # Operator: 'not_equals' / 'ne'
    if "not_equals" in condition or "ne" in condition:
        target = condition.get("not_equals", condition.get("ne"))
        if actual_value is not None:
            return (actual_value != target and str(actual_value) != str(target)), actual_value
        return False, actual_value

    # Operator: 'not_in'
    if "not_in" in condition:
        disallowed = condition["not_in"]
        if isinstance(disallowed, list):
            if actual_value is not None:
                disallowed_str = [str(x) for x in disallowed]
                if actual_value not in disallowed and str(actual_value) not in disallowed_str:
                    return True, actual_value
        return False, actual_value

    return False, actual_value


def format_finding_message(template: str, value: Any, attribute: Optional[str] = None) -> str:
    """Format finding message template with attribute value."""
    try:
        return template.format(
            value=value if value is not None else "unknown", attribute=attribute or ""
        )
    except Exception:
        return template


def evaluate_resource_against_rule(resource: Resource, rule: Dict[str, Any]) -> Optional[Finding]:
    """
    Evaluate a single resource against a declarative rule.

    Returns:
        - Finding with base_severity if vulnerable.
        - Finding with Severity.UNKNOWN if attribute required by rule cannot be resolved offline.
        - None if evaluated and safe.
    """
    target_type = rule.get("resource_type")
    if not target_type or resource.type != target_type:
        return None

    condition = rule.get("condition")
    if not isinstance(condition, dict):
        return None

    # Fallback to provider defaults if resource was constructed directly without parser
    effective_attrs = apply_provider_defaults(resource.type, resource.attributes)

    matched, attr_value = evaluate_condition(condition, effective_attrs)

    raw_exposure = str(rule.get("exposure", "authenticity")).lower()
    try:
        exposure = ExposureType(raw_exposure)
    except ValueError:
        exposure = ExposureType.AUTHENTICITY

    # Dynamic exposure mapping for aws_kms_key (K4)
    if resource.type == "aws_kms_key":
        key_usage = str(effective_attrs.get("key_usage", "")).upper()
        if key_usage == "ENCRYPT_DECRYPT":
            exposure = ExposureType.CONFIDENTIALITY
        else:
            exposure = ExposureType.AUTHENTICITY

    references = rule.get("references", [])
    if isinstance(references, str):
        references = [references]
    elif not isinstance(references, list):
        references = []

    # If condition could not be evaluated due to UNKNOWN attribute
    if matched is None:
        attr_name = condition.get("attribute", "unknown")
        raw_val = attr_value if attr_value is not None else UNKNOWN
        message = (
            f"Rule {rule.get('id', '')} could not be evaluated: attribute '{attr_name}' "
            f"is unresolved offline ({raw_val})."
        )
        return Finding(
            rule_id=str(rule.get("id", "UNKNOWN-RULE")),
            rule_title=str(rule.get("title", "")),
            resource=resource,
            severity=Severity.UNKNOWN,
            exposure=exposure,
            message=message,
            remediation_ref=rule.get("remediation_ref"),
            references=[str(ref) for ref in references],
        )

    if not matched:
        return None

    # Determine Severity and Exposure
    raw_severity = str(rule.get("base_severity", "high")).lower()
    try:
        severity = Severity(raw_severity)
    except ValueError:
        severity = Severity.HIGH

    message_template = str(rule.get("message", "Quantum-vulnerable configuration detected."))
    message = format_finding_message(
        template=message_template,
        value=attr_value,
        attribute=condition.get("attribute"),
    )

    return Finding(
        rule_id=str(rule.get("id", "UNKNOWN-RULE")),
        rule_title=str(rule.get("title", "")),
        resource=resource,
        severity=severity,
        exposure=exposure,
        message=message,
        remediation_ref=rule.get("remediation_ref"),
        references=[str(ref) for ref in references],
    )


class RuleEngine:
    """Declarative Rule Engine that evaluates YAML rules against normalized resources."""

    def __init__(
        self,
        rules_dir: Optional[Union[str, Path]] = None,
        rules: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        self.unresolved_count: int = 0
        self.unresolved_attributes: List[Dict[str, Any]] = []
        if rules is not None:
            self.rules = list(rules)
        else:
            self.rules = self.load_rules(self.rules_dir)

    def load_rules(self, rules_dir: Optional[Union[str, Path]] = None) -> List[Dict[str, Any]]:
        """Load or reload rules from the specified directory."""
        target_dir = Path(rules_dir) if rules_dir else self.rules_dir
        if not target_dir.exists() and DEFAULT_RULES_DIR.exists():
            target_dir = DEFAULT_RULES_DIR
        self.rules = load_rules_from_dir(target_dir)
        return self.rules

    def evaluate_resource(self, resource: Resource) -> List[Finding]:
        """Evaluate a single resource against all loaded rules."""
        findings: List[Finding] = []
        for rule in self.rules:
            finding = evaluate_resource_against_rule(resource, rule)
            if finding:
                if finding.severity == Severity.UNKNOWN:
                    self.unresolved_count += 1
                    self.unresolved_attributes.append(
                        {
                            "resource": f"{resource.type}.{resource.name}",
                            "rule_id": finding.rule_id,
                            "message": finding.message,
                        }
                    )
                findings.append(finding)
        return findings

    def evaluate(self, resources: List[Resource]) -> List[Finding]:
        """
        Evaluate a collection of resources against all loaded rules.
        Returns findings sorted deterministically.
        """
        self.unresolved_count = 0
        self.unresolved_attributes = []
        findings: List[Finding] = []
        for resource in resources:
            findings.extend(self.evaluate_resource(resource))

        # Deterministic sorting: severity rank, resource type, resource name, rule id
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
            Severity.UNKNOWN: 5,
        }
        findings.sort(
            key=lambda f: (
                severity_order.get(f.severity, 99),
                f.resource.type,
                f.resource.name,
                f.rule_id,
            )
        )
        return findings


def evaluate_rules(
    resources: List[Resource],
    rules: Optional[List[Dict[str, Any]]] = None,
    rules_dir: Optional[Union[str, Path]] = None,
) -> List[Finding]:
    """Functional convenience entry point to evaluate resources against rules."""
    engine = RuleEngine(rules_dir=rules_dir, rules=rules)
    return engine.evaluate(resources)
