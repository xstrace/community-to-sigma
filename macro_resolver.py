"""
Macro Resolver for Splunk Security Content.

Loads and classifies all macros from the security_content repo.
Resolves macro references in SPL detection rules.
"""

import os
import glob
import yaml
import re
from dataclasses import dataclass, field


@dataclass
class Macro:
    name: str
    definition: str
    args: list[str]
    description: str

    # Classification
    macro_type: str = "unknown"  # data_source, process_filter, utility, complex, lookup, time_window

    # For data_source macros: extracted logsource info
    source: str | None = None
    sourcetype: str | None = None
    index: str | None = None
    eventtype: str | None = None
    channel: str | None = None

    # For process_filter macros: parsed conditions
    conditions: list[dict] = field(default_factory=list)


class MacroResolver:
    """Resolves Splunk macros to their definitions and extracts metadata."""

    # Macros to always skip (Splunk-internal utilities)
    UTILITY_MACROS = {
        "security_content_summariesonly", "security_content_ctime",
        "summariesonly_config", "oldsummaries_config", "fillnull_config",
    }

    # Macros whose usage means the detection is too complex for Sigma
    COMPLEX_MACROS = {
        "base64decode", "normalized_service_binary_field",
        "potentially_malicious_code_on_cmdline_tokenize_score",
        "potential_password_in_username_false_positive_reduction",
        "remote_access_software_usage_exceptions",
        "secureapp_es_field_mappings",
    }

    # Macros that involve lookups
    LOOKUP_MACROS = {
        "suspicious_writes", "remove_valid_domains",
    }

    # Time-window macros (used in ML-based detections)
    TIME_WINDOW_MACROS = {
        "previously_seen_cloud_api_calls_per_user_role_forget_window",
        "previously_seen_cloud_compute_images_forget_window",
        "previously_seen_cloud_compute_instance_type_forget_window",
        "previously_seen_cloud_provisioning_activity_forget_window",
        "previously_seen_cloud_region_forget_window",
        "previously_seen_windows_services_forget_window",
        "previously_seen_windows_services_window",
        "previously_seen_zoom_child_processes_forget_window",
        "previously_seen_zoom_child_processes_window",
        "previously_unseen_cloud_provisioning_activity_window",
    }

    def __init__(self, macro_dir: str):
        self.macros: dict[str, Macro] = {}
        self._load_macros(macro_dir)

    def _load_macros(self, macro_dir: str):
        """Load all macro YAML files from the macro directory."""
        for fpath in sorted(glob.glob(os.path.join(macro_dir, "*.yml"))):
            with open(fpath) as f:
                data = yaml.safe_load(f)
            name = os.path.basename(fpath).replace(".yml", "")
            macro = Macro(
                name=name,
                definition=str(data.get("definition", "")),
                args=data.get("arguments", []),
                description=str(data.get("description", "")),
            )
            self._classify(macro)
            self.macros[name] = macro

    def _classify(self, macro: Macro):
        """Classify a macro and extract relevant metadata."""
        name = macro.name
        defn = macro.definition

        # Utility macros
        if name in self.UTILITY_MACROS:
            macro.macro_type = "utility"
            return

        # Time window macros
        if name in self.TIME_WINDOW_MACROS:
            macro.macro_type = "time_window"
            return

        # Complex macros
        if name in self.COMPLEX_MACROS:
            macro.macro_type = "complex"
            return

        # Lookup macros
        if name in self.LOOKUP_MACROS:
            macro.macro_type = "lookup"
            return

        # Macros containing SPL pipes or complex eval
        if "|" in defn:
            if "lookup" not in defn.lower():
                # Piped macros are usually complex transformations
                macro.macro_type = "complex"
                return

        if any(kw in defn.lower() for kw in [
            "lookup ", "inputlookup", "outputlookup",
            "split(", "mvjoin(", "makemv ", "spath ",
        ]):
            macro.macro_type = "lookup"
            return

        # Extract source/sourcetype/index from data source macros
        data_source_info = self._extract_data_source_info(defn)
        if data_source_info["has_source_info"]:
            macro.macro_type = "data_source"
            macro.source = data_source_info["source"]
            macro.sourcetype = data_source_info["sourcetype"]
            macro.index = data_source_info["index"]
            macro.eventtype = data_source_info["eventtype"]
            macro.channel = data_source_info["channel"]
            return

        # Process filter macros (contain Processes. or process_name/Image conditions)
        if self._is_process_filter(defn):
            macro.macro_type = "process_filter"
            macro.conditions = self._parse_process_conditions(defn)
            return

        # General condition macros (contain field=value conditions)
        if "=" in defn or " IN " in defn:
            macro.macro_type = "condition_filter"
            return

        # Default
        macro.macro_type = "other"

    def _extract_data_source_info(self, defn: str) -> dict:
        """Extract source, sourcetype, index, eventtype, channel from a macro definition."""
        info = {
            "has_source_info": False,
            "source": None,
            "sourcetype": None,
            "index": None,
            "eventtype": None,
            "channel": None,
        }

        data_source_keywords = ["source=", "sourcetype=", "index=", "eventtype=", "Channel="]
        if not any(kw in defn.lower() for kw in data_source_keywords):
            return info

        info["has_source_info"] = True

        # Extract individual fields
        for pattern, key in [
            (r'source\s*=\s*"([^"]+)"', "source"),
            (r'source\s*=\s*([^\s)]+)', "source"),
            (r'sourcetype\s*=\s*"([^"]+)"', "sourcetype"),
            (r'sourcetype\s*=\s*([^\s)]+)', "sourcetype"),
            (r'index\s*=\s*([^\s)]+)', "index"),
            (r'eventtype\s*=\s*"([^"]+)"', "eventtype"),
            (r'eventtype\s*=\s*([^\s)]+)', "eventtype"),
            (r'Channel\s*=\s*"([^"]+)"', "channel"),
            (r'Channel\s*=\s*([^\s)]+)', "channel"),
        ]:
            match = re.search(pattern, defn)
            if match:
                info[key] = match.group(1).strip()

        return info

    def _is_process_filter(self, defn: str) -> bool:
        """Check if a macro definition is a process name filter."""
        return bool(
            re.search(r'Processes\.(process_name|original_file_name|parent_process_name)\s*[=!]', defn)
            or re.search(r'(process_name|original_file_name)\s*IN\s*\(', defn)
        )

    def _parse_process_conditions(self, defn: str) -> list[dict]:
        """Parse process filter conditions from a macro definition."""
        conditions = []

        # Parse: Processes.field=value OR Processes.field=value
        # Simple regex-based extraction (acceptable here since we're parsing
        # macro definitions, not full SPL)
        for match in re.finditer(
            r'Processes\.(\w+)\s*(=|!=)\s*"?([^")]+)"?',
            defn
        ):
            field = match.group(1)
            op = match.group(2)
            value = match.group(3).rstrip('"').rstrip(")")
            conditions.append({
                "field": f"Processes.{field}",
                "op": op,
                "value": value,
            })

        # Also handle IN clauses
        in_match = re.search(
            r'Processes\.(\w+)\s+IN\s+\(([^)]+)\)',
            defn
        )
        if in_match:
            field = in_match.group(1)
            values_str = in_match.group(2)
            # Parse comma-separated quoted values
            values = []
            for v in re.findall(r'"([^"]*)"', values_str) or re.findall(r'([^,\s]+)', values_str):
                values.append(v.strip())
            if values:
                conditions.append({
                    "field": f"Processes.{field}",
                    "op": "IN",
                    "value": values,
                })

        return conditions

    def resolve(self, macro_name: str, depth: int = 0) -> dict | None:
        """Resolve a macro by name, returning its parsed information.
        Strips backticks from the name if present.
        """
        if depth > 5:
            return None  # prevent infinite recursion

        name = macro_name.strip("`")
        macro = self.macros.get(name)
        if macro is None:
            return None

        # Check if definition references other macros recursively
        definition = macro.definition
        refs = re.findall(r'`([^`]+)`', definition)
        if refs and depth < 5:
            for ref in refs:
                resolved = self.resolve(ref, depth + 1)
                if resolved and resolved.get("type") in ("data_source", "condition_filter"):
                    # Replace the macro ref with its expanded form
                    # For now, just record the dependency
                    pass

        return {
            "name": name,
            "type": macro.macro_type,
            "definition": definition,
            "source": macro.source,
            "sourcetype": macro.sourcetype,
            "index": macro.index,
            "eventtype": macro.eventtype,
            "channel": macro.channel,
            "conditions": macro.conditions,
            "is_utility": macro.macro_type == "utility",
            "is_complex": macro.macro_type == "complex",
            "is_lookup": macro.macro_type == "lookup",
        }

    def get_logsource_hint(self, macro_name: str) -> dict | None:
        """Get Sigma logsource hints from a data source macro."""
        resolved = self.resolve(macro_name)
        if resolved is None or resolved["type"] != "data_source":
            return None
        return {
            "source": resolved["source"],
            "sourcetype": resolved["sourcetype"],
            "index": resolved["index"],
            "eventtype": resolved["eventtype"],
            "channel": resolved["channel"],
        }

    def is_macro_complex(self, macro_name: str) -> bool:
        """Check if a macro would make the detection too complex to convert."""
        resolved = self.resolve(macro_name)
        if resolved is None:
            return False
        return resolved["is_complex"] or resolved["is_lookup"]

    def is_macro_utility(self, macro_name: str) -> bool:
        """Check if a macro is a utility (should be stripped)."""
        resolved = self.resolve(macro_name)
        if resolved is None:
            return False
        return resolved["is_utility"]

    def get_process_conditions(self, macro_name: str) -> list[dict]:
        """Get expanded process conditions from a process_filter macro."""
        resolved = self.resolve(macro_name)
        if resolved is None or resolved["type"] != "process_filter":
            return []
        return resolved["conditions"]
