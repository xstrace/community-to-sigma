"""
Field and Logsource Mappings: Splunk CIM → Sigma Standard Fields.

Loads mappings from mappings.yml at runtime. Unknown entries fall back
to dynamic derivation: strip data model prefix, lowercase normalisation.
"""

import os
import yaml

_MAPPINGS = None


def _load():
    """Lazy-load mappings from YAML file."""
    global _MAPPINGS
    if _MAPPINGS is not None:
        return _MAPPINGS
    path = os.path.join(os.path.dirname(__file__), "mappings.yml")
    with open(path) as f:
        _MAPPINGS = yaml.safe_load(f)
    return _MAPPINGS


# ---------------------------------------------------------------------------
# Field mapping
# ---------------------------------------------------------------------------

def map_cim_field(field_name: str) -> str:
    """Map a Splunk CIM field name to a Sigma field name.

    Checks exact match first, then strips data model prefix
    and checks the bare field name. Falls back to original.
    """
    m = _load()
    field_map = m.get("fields", {})

    # Exact match
    if field_name in field_map:
        return field_map[field_name]

    # Strip data model prefix (Processes.X → X) and retry
    if "." in field_name:
        bare = field_name.split(".", 1)[1]
        if bare in field_map:
            return field_map[bare]

    return field_name


# ---------------------------------------------------------------------------
# Logsource mapping
# ---------------------------------------------------------------------------

def map_datamodel_to_logsource(datamodel_name: str) -> dict:
    """Map a Splunk CIM data model name to Sigma logsource fields."""
    m = _load()
    dm_map = m.get("datamodel_logsource", {})
    if datamodel_name in dm_map:
        return dict(dm_map[datamodel_name])
    return {"category": datamodel_name.lower().split(".")[-1]}


def map_macro_to_logsource(macro_name: str) -> dict | None:
    """Map a Splunk data source macro to Sigma logsource fields."""
    m = _load()
    macro_map = m.get("macro_logsource", {})
    name = macro_name.strip("`")
    if name in macro_map:
        return dict(macro_map[name])
    return None


# ---------------------------------------------------------------------------
# Path routing
# ---------------------------------------------------------------------------

def resolve_output_path(product: str, category: str, service: str) -> str:
    """Resolve the output directory path for a Sigma rule.

    Tries static mappings first, then falls back to dynamic derivation:
      {product}/{category_or_service}/ if product known
      other/{category_or_service}/ otherwise
    """
    m = _load()
    paths = m.get("paths", [])

    # Try exact match, then progressively looser
    for keys_order in [
        (product, category, service),
        (product, category, ""),
        (product, "", service),
        (product, "", ""),
        ("", category, ""),
        ("", "", service),
    ]:
        for entry in paths:
            ek = entry.get("keys", [])
            if len(ek) == 3 and ek[0] == keys_order[0] and ek[1] == keys_order[1] and ek[2] == keys_order[2]:
                return entry["path"]

    # Dynamic fallback
    if product:
        sub = category or service or product
        return f"{product}/{sub}"
    if category:
        return f"other/{category}"
    if service:
        return f"other/{service}"
    return "other/unknown"
