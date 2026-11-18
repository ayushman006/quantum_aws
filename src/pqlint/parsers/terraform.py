"""Offline Terraform HCL parser using python-hcl2 with variable and local resolution."""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    import hcl2  # type: ignore

    _HAS_HCL2 = True
except ImportError:
    _HAS_HCL2 = False

from pqlint.model import UNKNOWN, Location, Origin, Resource, is_unknown
from pqlint.parsers.defaults import apply_provider_defaults

IGNORED_DIRS = {".terraform", ".git"}


def _clean_str(s: str) -> str:
    """Strip leading and trailing quotes from a string."""
    return s.strip("\"'")


def _normalize_hcl_value(val: Any) -> Any:
    """Recursively clean python-hcl2 AST values into standard Python dicts/lists/scalars."""
    if isinstance(val, dict):
        cleaned_dict: Dict[str, Any] = {}
        for k, v in val.items():
            if k == "__is_block__":
                continue
            if k == "dynamic":
                # Unwrap Terraform dynamic blocks so inner attributes are accessible to rules
                dyn_blocks = v if isinstance(v, list) else [v]
                for dyn_block in dyn_blocks:
                    if isinstance(dyn_block, dict):
                        for dyn_name, dyn_spec in dyn_block.items():
                            if dyn_name == "__is_block__":
                                continue
                            clean_dyn_name = (
                                _clean_str(dyn_name) if isinstance(dyn_name, str) else dyn_name
                            )
                            if isinstance(dyn_spec, dict) and "content" in dyn_spec:
                                content_val = _normalize_hcl_value(dyn_spec["content"])
                                if clean_dyn_name in cleaned_dict:
                                    existing = cleaned_dict[clean_dyn_name]
                                    if isinstance(existing, list):
                                        if isinstance(content_val, list):
                                            existing.extend(content_val)
                                        else:
                                            existing.append(content_val)
                                    else:
                                        cleaned_dict[clean_dyn_name] = [existing, content_val]
                                else:
                                    cleaned_dict[clean_dyn_name] = content_val
                continue
            cleaned_key = _clean_str(k) if isinstance(k, str) else k
            cleaned_dict[cleaned_key] = _normalize_hcl_value(v)
        return cleaned_dict
    elif isinstance(val, list):
        return [_normalize_hcl_value(item) for item in val]
    elif isinstance(val, str):
        return _clean_str(val)
    return val


def _extract_variables_and_locals(
    parsed: Dict[str, Any],
    variables: Dict[str, Any],
    raw_locals: Dict[str, Any],
) -> None:
    """Extract variable blocks (with defaults) and locals blocks from a parsed HCL AST."""
    # 1. Variables
    for var_block in parsed.get("variable", []):
        if isinstance(var_block, dict):
            for raw_var_name, var_def in var_block.items():
                var_name = _clean_str(raw_var_name)
                if isinstance(var_def, dict) and "default" in var_def:
                    variables[var_name] = _normalize_hcl_value(var_def["default"])
                elif var_name not in variables:
                    variables[var_name] = UNKNOWN

    # 2. Locals
    for loc_block in parsed.get("locals", []):
        if isinstance(loc_block, dict):
            for raw_loc_name, loc_val in loc_block.items():
                if raw_loc_name == "__is_block__":
                    continue
                loc_name = _clean_str(raw_loc_name)
                raw_locals[loc_name] = _normalize_hcl_value(loc_val)


def _resolve_val(val: Any, variables: Dict[str, Any], locals_map: Dict[str, Any]) -> Any:
    """Recursively resolve variables and locals in an attribute value."""
    if isinstance(val, dict):
        return {k: _resolve_val(v, variables, locals_map) for k, v in val.items()}
    elif isinstance(val, list):
        return [_resolve_val(item, variables, locals_map) for item in val]
    elif isinstance(val, str):
        s = val.strip()

        # Exact match: ${var.foo} or var.foo
        m_var = re.match(r"^(\$\{)?var\.([a-zA-Z0-9_-]+)\}?$", s)
        if m_var:
            vname = m_var.group(2)
            if vname in variables and variables[vname] != UNKNOWN:
                return variables[vname]
            return UNKNOWN

        # Exact match: ${local.bar} or local.bar
        m_loc = re.match(r"^(\$\{)?local\.([a-zA-Z0-9_-]+)\}?$", s)
        if m_loc:
            lname = m_loc.group(2)
            if lname in locals_map and locals_map[lname] != UNKNOWN:
                return locals_map[lname]
            return UNKNOWN

        # Exact match: data source, module output, or resource attribute (unresolvable offline)
        m_ext = re.match(
            r"^(\$\{)?(module|data|aws_[a-zA-Z0-9_-]+)\.[a-zA-Z0-9_.-]+\}?$",
            s,
        )
        if m_ext:
            return UNKNOWN

        # Embedded interpolations: e.g. "prefix-${var.foo}-suffix"
        if "${" in s:
            has_unknown = False

            def replace_expr(match: re.Match) -> str:
                nonlocal has_unknown
                expr = match.group(1).strip()
                if expr.startswith("var."):
                    vname = expr[4:].strip()
                    if vname in variables and variables[vname] != UNKNOWN:
                        return str(variables[vname])
                    has_unknown = True
                    return UNKNOWN
                elif expr.startswith("local."):
                    lname = expr[6:].strip()
                    if lname in locals_map and locals_map[lname] != UNKNOWN:
                        return str(locals_map[lname])
                    has_unknown = True
                    return UNKNOWN
                else:
                    has_unknown = True
                    return UNKNOWN

            resolved_str = re.sub(r"\$\{([^}]+)\}", replace_expr, s)
            if has_unknown or UNKNOWN in resolved_str:
                return UNKNOWN
            return resolved_str

        return val

    return val


def _resolve_locals(raw_locals: Dict[str, Any], variables: Dict[str, Any]) -> Dict[str, Any]:
    """Iteratively resolve local values against variables and other locals."""
    resolved_locals = dict(raw_locals)
    for _ in range(10):
        changed = False
        for k, v in list(resolved_locals.items()):
            new_v = _resolve_val(v, variables, resolved_locals)
            if new_v != resolved_locals[k]:
                resolved_locals[k] = new_v
                changed = True
        if not changed:
            break
    return resolved_locals


def _extract_resources_from_parsed(
    parsed: Dict[str, Any],
    file_name: str,
    variables: Dict[str, Any],
    locals_map: Dict[str, Any],
) -> List[Resource]:
    """Extract and resolve normalized Resource objects from a parsed HCL file."""
    resources: List[Resource] = []
    resource_blocks = parsed.get("resource", [])
    if not isinstance(resource_blocks, list):
        return []

    for block in resource_blocks:
        if not isinstance(block, dict):
            continue

        for raw_type, instances in block.items():
            resource_type = _clean_str(raw_type)

            if not isinstance(instances, dict):
                continue

            for raw_name, raw_attrs in instances.items():
                resource_name = _clean_str(raw_name)

                if isinstance(raw_attrs, dict):
                    attributes = _normalize_hcl_value(raw_attrs)
                    # Resolve variable and local references offline
                    attributes = _resolve_val(attributes, variables, locals_map)
                else:
                    attributes = {}

                # Apply AWS provider defaults for unconfigured attributes
                attributes = apply_provider_defaults(resource_type, attributes)

                # Check for count meta-argument (N3)
                raw_count = attributes.get("count")
                count_val: Optional[int] = None
                if raw_count is not None and not is_unknown(raw_count):
                    try:
                        if isinstance(raw_count, bool):
                            count_val = None
                        elif isinstance(raw_count, (int, float)):
                            count_val = int(raw_count)
                        elif isinstance(raw_count, str) and raw_count.strip().isdigit():
                            count_val = int(raw_count.strip())
                        elif isinstance(raw_count, list) and len(raw_count) == 1:
                            item = raw_count[0]
                            if not isinstance(item, bool) and isinstance(item, (int, float)):
                                count_val = int(item)
                            elif isinstance(item, str) and item.strip().isdigit():
                                count_val = int(item.strip())
                    except (ValueError, TypeError):
                        count_val = None

                if count_val is not None:
                    if count_val == 0:
                        continue
                    elif count_val > 0:
                        for idx in range(count_val):
                            resources.append(
                                Resource(
                                    type=resource_type,
                                    name=f"{resource_name}[{idx}]",
                                    provider_id=None,
                                    attributes=dict(attributes),
                                    location=Location(file_path=file_name),
                                    origin=Origin.IAC,
                                )
                            )
                        continue

                # If count is absent or unresolvable, yield the standard base name
                resources.append(
                    Resource(
                        type=resource_type,
                        name=resource_name,
                        provider_id=None,
                        attributes=attributes,
                        location=Location(file_path=file_name),
                        origin=Origin.IAC,
                    )
                )

    return resources


def parse_terraform_file(
    file_path: Union[str, Path], warnings: Optional[List[str]] = None
) -> List[Resource]:
    """Parse a single .tf file into a list of normalized Resource objects."""
    if not _HAS_HCL2:
        return []

    path = Path(file_path)
    if not path.is_file() or path.suffix.lower() != ".tf":
        return []

    if any(part in IGNORED_DIRS for part in path.parts):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            parsed = hcl2.load(f)
    except Exception as e:
        if warnings is not None:
            warnings.append(f"Failed to read or parse '{path}': {e}")
        return []

    if not isinstance(parsed, dict) or "resource" not in parsed:
        return []

    variables: Dict[str, Any] = {}
    raw_locals: Dict[str, Any] = {}
    _extract_variables_and_locals(parsed, variables, raw_locals)
    locals_map = _resolve_locals(raw_locals, variables)

    return _extract_resources_from_parsed(parsed, path.name, variables, locals_map)


def parse_terraform_directory(
    target_dir: Union[str, Path], warnings: Optional[List[str]] = None
) -> List[Resource]:
    """
    Scans a directory for all .tf files offline and converts them into normalized Resource objects.
    Resolves variables (with defaults) and locals across the directory module scope.
    Zero network calls and never shells out to terraform.
    """
    path = Path(target_dir)
    if not path.exists():
        return []

    if path.is_file() and path.suffix.lower() == ".tf":
        if any(part in IGNORED_DIRS for part in path.parts):
            return []
        return parse_terraform_file(path, warnings=warnings)

    tf_files = sorted(list(path.glob("*.tf")) + list(path.glob("**/*.tf")))
    seen_paths = set()
    unique_files: List[Path] = []
    for f in tf_files:
        if any(part in IGNORED_DIRS for part in f.parts):
            continue
        resolved = f.resolve()
        if resolved not in seen_paths:
            seen_paths.add(resolved)
            unique_files.append(f)

    if not unique_files:
        return []

    # Pass 1: Parse AST and collect variables and locals across all files in directory
    parsed_files: List[Tuple[Path, Dict[str, Any]]] = []
    variables: Dict[str, Any] = {}
    raw_locals: Dict[str, Any] = {}

    for tf_file in unique_files:
        try:
            with open(tf_file, "r", encoding="utf-8") as file_handle:
                parsed = hcl2.load(file_handle)
                if isinstance(parsed, dict):
                    parsed_files.append((tf_file, parsed))
                    _extract_variables_and_locals(parsed, variables, raw_locals)
        except Exception as e:
            if warnings is not None:
                warnings.append(f"Failed to read or parse '{tf_file}': {e}")
            continue

    # Resolve locals across the directory scope
    locals_map = _resolve_locals(raw_locals, variables)

    # Pass 2: Extract resources with resolved variable and local values
    resources: List[Resource] = []
    for tf_file, parsed in parsed_files:
        resources.extend(
            _extract_resources_from_parsed(parsed, tf_file.name, variables, locals_map)
        )

    return resources
