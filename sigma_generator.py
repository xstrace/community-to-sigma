"""
Sigma Rule Generator.

Converts parsed SPL AST and detection metadata into Sigma rules
using the pysigma (sigma.rule) library.
"""

import uuid
import datetime
import os
import yaml
from typing import Any

# Custom YAML dumper that doesn't escape >, <, & in string values
class _NoEscapeDumper(yaml.Dumper):
    pass

def _str_representer(dumper, data):
    if '\n' in data:
        return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
    return dumper.represent_scalar('tag:yaml.org,2002:str', data)

_NoEscapeDumper.add_representer(str, _str_representer)

from sigma.rule import (
    SigmaRule, SigmaLogSource, SigmaDetection, SigmaDetectionItem,
    SigmaDetections, SigmaLevel, SigmaStatus, SigmaRuleTag,
)
from sigma.conditions import ConditionAND, ConditionOR
from sigma.types import SigmaString, SigmaNumber

from mappings import (
    map_cim_field, map_datamodel_to_logsource, map_macro_to_logsource,
    CIM_FIELD_MAP, COMMON_FIELD_ALIASES,
)
from classifier import classify_detection
from macro_resolver import MacroResolver


class SigmaGenerator:
    """Generates Sigma rules from parsed Splunk detections."""

    def __init__(self, macro_resolver: MacroResolver):
        self.macro_resolver = macro_resolver

    def generate(
        self,
        detection_yaml: dict,
        ast: dict,
        classification: dict,
        output_dir: str,
    ) -> str | None:
        """
        Convert a Splunk detection to a Sigma rule and write to file.

        Args:
            detection_yaml: Original Splunk detection YAML data
            ast: Parsed SPL AST
            classification: Classification info from classifier
            output_dir: Base output directory

        Returns:
            Path to generated Sigma file, or None if skipped
        """
        # Determine logsource
        logsource = self._determine_logsource(detection_yaml, ast, classification)

        # Build detection selections from SPL conditions
        selections, condition_expr = self._build_detections(ast, classification)

        if not selections:
            return None  # Nothing to detect

        # Build Sigma rule
        try:
            rule = self._build_rule(detection_yaml, logsource, selections, condition_expr)
        except Exception as e:
            print(f"    WARNING: Failed to build rule: {e}")
            return None

        # Determine output path
        out_path = self._get_output_path(output_dir, rule, detection_yaml)

        # Write to file
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        try:
            rule_dict = rule.to_dict()
            with open(out_path, "w") as f:
                yaml.dump(rule_dict, f, Dumper=_NoEscapeDumper,
                          default_flow_style=False, allow_unicode=True,
                          sort_keys=False, indent=2, width=200)
            # Post-process: fix pysigma-internal HTML entity escaping in values.
            # pysigma's to_dict() encodes >, <, & as HTML entities in some
            # contexts. We undo that here since YAML doesn't require them.
            with open(out_path) as f:
                content = f.read()
            content = content.replace("&gt;", ">").replace("&lt;", "<").replace("&amp;", "&")
            with open(out_path, "w") as f:
                f.write(content)
        except Exception as e:
            print(f"    WARNING: Failed to write rule: {e}")
            return None

        return out_path

    def _determine_logsource(
        self, detection_yaml: dict, ast: dict, classification: dict
    ) -> SigmaLogSource:
        """Determine the Sigma logsource from the Splunk detection."""
        logsource_kwargs: dict[str, str] = {}

        hints = classification.get("logsource_hints", {})

        # Try data model mapping
        data_model = hints.get("data_model")
        if data_model:
            dm_ls = map_datamodel_to_logsource(data_model)
            logsource_kwargs.update(dm_ls)

        # Try macro-based mapping (overrides data model if more specific)
        macro_name = hints.get("macro")
        if macro_name:
            macro_ls = map_macro_to_logsource(macro_name)
            if macro_ls:
                logsource_kwargs.update(macro_ls)

        # Detect Linux-specific patterns
        is_linux = self._is_linux_detection(detection_yaml, ast, hints)

        # If auditd service is detected, force Linux
        macro_info = hints.get("macro_info", {})
        if macro_info.get("sourcetype") and "auditd" in str(macro_info.get("sourcetype")).lower():
            is_linux = True

        # Normalize category names that include data model prefixes
        category_val = logsource_kwargs.get("category", "")
        if category_val and "." in category_val:
            # e.g., "network_traffic.all_traffic" → "network_traffic"
            logsource_kwargs["category"] = category_val.split(".")[-1]

        # Fall back to detection category
        if not logsource_kwargs:
            category = detection_yaml.get("category", "")
            if category == "endpoint":
                if is_linux:
                    logsource_kwargs = {"product": "linux", "category": "process_creation"}
                else:
                    logsource_kwargs = {"product": "windows", "category": "process_creation"}
            elif category == "web":
                logsource_kwargs = {"category": "webserver"}
            elif category == "network":
                logsource_kwargs = {"category": "network_connection"}
            elif category == "cloud":
                logsource_kwargs = {"product": "aws", "service": "cloudtrail"}
            elif category == "application":
                logsource_kwargs = {"category": "application"}
            else:
                # No category either — use heuristics
                if is_linux:
                    logsource_kwargs = {"product": "linux", "category": "process_creation"}
                else:
                    logsource_kwargs = {"category": "process_creation"}

        # Ensure Linux detections have product set
        if is_linux and not logsource_kwargs.get("product"):
            logsource_kwargs["product"] = "linux"

        # Detect product hints from rule metadata (title, macro, etc.)
        product_hint = self._detect_product_hints(detection_yaml, hints)
        if product_hint and not logsource_kwargs.get("product"):
            logsource_kwargs["product"] = product_hint
        elif is_linux and logsource_kwargs.get("product") == "windows":
            # Override windows→linux for Linux detections
            logsource_kwargs["product"] = "linux"

        # Add definition hint from macro source info
        definition_parts = []
        macro_info = hints.get("macro_info", {})
        if macro_info:
            parts = []
            if macro_info.get("source"):
                definition_parts.append(f"source={macro_info['source']}")
            if macro_info.get("sourcetype"):
                definition_parts.append(f"sourcetype={macro_info['sourcetype']}")
            if macro_info.get("index"):
                definition_parts.append(f"index={macro_info['index']}")
            if macro_info.get("channel"):
                definition_parts.append(f"channel={macro_info['channel']}")
            if parts:
                logsource_kwargs["definition"] = "; ".join(parts)

        return SigmaLogSource(**{
            k: v for k, v in logsource_kwargs.items()
            if k in ("category", "product", "service", "definition")
        })

    def _is_linux_detection(
        self, detection_yaml: dict, ast: dict, hints: dict
    ) -> bool:
        """Heuristic to detect if a detection targets Linux."""
        # Check data source
        data_sources = detection_yaml.get("data_source", [])
        if isinstance(data_sources, list):
            for ds in data_sources:
                ds_lower = str(ds).lower()
                if any(kw in ds_lower for kw in ["linux", "unix", "auditd", "audit"]):
                    return True

        # Check macro name
        macro_name = (hints.get("macro", "") or "").lower()
        if any(kw in macro_name for kw in ["linux", "unix", "auditd"]):
            return True

        # Check if detection name/description mentions Linux
        name = str(detection_yaml.get("name", "")).lower()
        desc = str(detection_yaml.get("description", "")).lower()
        if name.startswith("linux") or "linux" in name[:20] or "unix" in name[:20]:
            return True
        if "linux" in desc[:100] or "unix" in desc[:100]:
            return True

        # Check for Linux-specific processes
        if "auditd" in name or "auditd" in desc[:200]:
            return True

        return False

    def _detect_product_hints(
        self, detection_yaml: dict, hints: dict
    ) -> str | None:
        """Detect product/platform hints from rule metadata."""
        title = str(detection_yaml.get("name", "")).lower()
        desc = str(detection_yaml.get("description", "")).lower()
        combined = title + " " + desc[:200]

        # Check macro hints
        macro_name = (hints.get("macro", "") or "").lower()
        macro_info = hints.get("macro_info", {})
        sourcetype = str(macro_info.get("sourcetype", "")).lower()
        source = str(macro_info.get("source", "")).lower()

        # Okta
        if any(kw in macro_name or kw in sourcetype or kw in title
               for kw in ["okta", "pingid"]):
            return "okta"

        # Cisco
        if any(kw in macro_name or kw in sourcetype or kw in title
               for kw in ["cisco"]):
            return "cisco"

        # AWS
        if any(kw in macro_name or kw in sourcetype or kw in title
               for kw in ["aws", "cloudtrail", "amazon"]):
            return "aws"

        # Azure
        if any(kw in macro_name or kw in sourcetype or kw in title
               for kw in ["azure"]):
            return "azure"

        # GCP / Google
        if any(kw in macro_name or kw in sourcetype or kw in title
               for kw in ["gcp", "google", "gsuite", "gws"]):
            return "gcp"

        # M365 / Office
        if any(kw in macro_name or kw in sourcetype or kw in title
               for kw in ["o365", "m365", "office 365", "microsoft 365",
                          "ms365", "msexchange"]):
            return "m365"

        # GitHub
        if any(kw in macro_name or kw in sourcetype or kw in title
               for kw in ["github"]):
            return "github"

        # Kubernetes
        if any(kw in macro_name or kw in sourcetype or kw in title
               for kw in ["kubernetes", "kube"]):
            return "kubernetes"

        # Zeek
        if any(kw in macro_name or kw in sourcetype
               for kw in ["zeek", "suricata"]):
            return "zeek"

        # CrowdStrike
        if any(kw in macro_name or kw in sourcetype
               for kw in ["crowdstrike"]):
            return "crowdstrike"

        # Active Directory
        if "ad " in title or title.startswith("ad ") or "active directory" in title:
            return "windows"

        # Windows (last resort guess for endpoint detections)
        if any(kw in title for kw in ["windows ", "win ", "powershell ",
                                       "sysmon ", "microsoft "]):
            return "windows"

        return None

    def _build_detections(
        self, ast: dict, classification: dict
    ) -> tuple[dict, list[str]]:
        """
        Build Sigma detection selections from the SPL AST conditions.

        Returns:
            (selections_dict, condition_expression)
        """
        conditions = classification.get("conditions")
        if conditions is None:
            # Try to extract conditions from search stages
            for stage in ast.get("stages", []):
                if stage.get("type") == "search":
                    conditions = stage.get("condition")
                    break
            if conditions is None:
                # Try tstats where clause
                for stage in ast.get("stages", []):
                    if stage.get("type") == "command" and stage.get("command") == "tstats":
                        conditions = stage.get("where")
                        break

        if conditions is None:
            return {}, []

        # Convert the boolean expression tree to Sigma detection items
        selections = {}
        counter = [0]  # mutable counter for naming selections

        try:
            self._convert_condition(conditions, selections, counter, is_top=True)
        except Exception as e:
            print(f"    WARNING: Failed to convert conditions: {e}")
            return {}, []

        if not selections:
            return {}, []

        # Build condition expression
        condition_expr = self._build_condition_expr(selections)
        return selections, [condition_expr]

    def _convert_condition(
        self, node: dict, selections: dict, counter: list, is_top: bool = False
    ):
        """Recursively convert a boolean expression AST node to Sigma detection items."""
        if not isinstance(node, dict):
            return

        node_type = node.get("type", "")

        if node_type in ("and", "or"):
            # For AND at the top level, flatten into one selection
            # For OR, create separate selections
            if node_type == "and" and is_top:
                self._convert_condition(node["left"], selections, counter, is_top=True)
                self._convert_condition(node["right"], selections, counter, is_top=True)
            elif node_type == "or":
                self._convert_condition(node["left"], selections, counter)
                self._convert_condition(node["right"], selections, counter)
            else:
                # Nested AND: create a new selection group
                sel_name = f"selection_{counter[0]}"
                counter[0] += 1
                inner = {}
                self._flatten_and(node, inner, counter)
                if inner:
                    selections[sel_name] = self._make_detection(inner)

        elif node_type == "not":
            sel_name = f"filter_{counter[0]}"
            counter[0] += 1
            inner = {}
            self._flatten_and(node["expr"], inner, counter, negate=True)
            if inner:
                selections[sel_name] = SigmaDetection(
                    detection_items=self._make_detection_items(inner),
                )

        elif node_type in ("eq", "ne", "gt", "lt", "ge", "le", "in"):
            # Single comparison → becomes a selection
            sel_name = f"selection_{counter[0]}"
            counter[0] += 1
            items = self._convert_comparison(node)
            if items:
                selections[sel_name] = SigmaDetection(
                    detection_items=items,
                    item_linking=ConditionAND,
                )

        elif node_type == "field":
            # Bare field reference — ignore (no condition)
            pass

        elif node_type == "atom":
            # Bare atom — ignore (Splunk keyword)
            pass

        elif node_type == "function_call":
            # Function call — too complex for Sigma simple matching
            pass

        elif node_type == "macro":
            # Unresolved macro — skip
            pass

        else:
            # Unknown — try to recurse into children
            for key, value in node.items():
                if key == "type":
                    continue
                if isinstance(value, dict):
                    self._convert_condition(value, selections, counter)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, dict):
                            self._convert_condition(item, selections, counter)

    def _flatten_and(
        self, node: dict, items: dict, counter: list, negate: bool = False
    ):
        """Flatten an AND-tree into a dict of field→value mappings."""
        if not isinstance(node, dict):
            return

        node_type = node.get("type", "")

        if node_type == "and":
            self._flatten_and(node["left"], items, counter, negate)
            self._flatten_and(node["right"], items, counter, negate)

        elif node_type in ("eq", "ne", "gt", "lt", "ge", "le", "in"):
            field, value, mod = self._extract_field_value(node)
            if field:
                field = map_cim_field(field)
                if negate:
                    # Negate: use != instead of =, or NOT IN instead of IN
                    pass
                key = f"{field}|{mod}" if mod else field
                if key not in items:
                    items[key] = value
                elif isinstance(items[key], list):
                    if isinstance(value, list):
                        items[key].extend(value)
                    else:
                        items[key].append(value)

        elif node_type == "field":
            # Bare field reference — skip
            pass

        elif node_type == "not":
            self._flatten_and(node["expr"], items, counter, negate=not negate)

    def _extract_field_value(self, node: dict) -> tuple[str | None, Any, str | None]:
        """Extract (field_name, value, modifier) from a comparison node."""
        node_type = node.get("type", "")
        field_node = node.get("field", {})
        value_node = node.get("value", {})

        if not isinstance(field_node, dict):
            return None, None, None

        field_name = field_node.get("raw", "")
        if not field_name:
            parts = field_node.get("parts", [])
            field_name = ".".join(parts) if parts else None

        if not field_name:
            return None, None, None

        # Extract value
        value = None
        modifier = None

        if node_type == "in":
            values_list = node.get("values", [])
            value = []
            for v in values_list:
                if isinstance(v, dict):
                    val = self._extract_raw_value(v)
                    if val:
                        value.append(val)
                elif isinstance(v, str):
                    value.append(v)
            if not value:
                value = None
        else:
            if isinstance(value_node, dict):
                value = self._extract_raw_value(value_node)
                if value and "*" in str(value):
                    modifier = "contains"

        return field_name, value, modifier

    def _extract_raw_value(self, value_node: dict) -> str | int | float | None:
        """Extract raw value from a value AST node."""
        if not isinstance(value_node, dict):
            return str(value_node)

        node_type = value_node.get("type", "")
        raw_value = value_node.get("value", "")

        if node_type == "string":
            # Strip surrounding quotes
            val = raw_value
            if val and val[0] in ('"', "'"):
                val = val[1:]
            if val and val[-1] in ('"', "'"):
                val = val[:-1]
            return val

        elif node_type == "number":
            try:
                return int(raw_value)
            except ValueError:
                try:
                    return float(raw_value)
                except ValueError:
                    return raw_value

        elif node_type == "wildcard":
            return raw_value

        elif node_type == "word":
            return raw_value

        else:
            return raw_value

    def _convert_comparison(self, node: dict) -> list[SigmaDetectionItem]:
        """Convert a single comparison node to SigmaDetectionItem list."""
        field_name, value, modifier = self._extract_field_value(node)
        if not field_name or value is None:
            return []

        # Map field name
        field_name = map_cim_field(field_name)

        # Build detection item
        try:
            if isinstance(value, list):
                # Handle list as a modified contains|all
                item = SigmaDetectionItem.from_mapping(
                    f"{field_name}|contains", value
                )
            elif modifier == "contains":
                item = SigmaDetectionItem.from_mapping(
                    f"{field_name}|{modifier}", value
                )
            else:
                item = SigmaDetectionItem.from_mapping(field_name, value)
            return [item]
        except Exception:
            return []

    def _make_detection(self, items_dict: dict) -> SigmaDetection:
        """Create a SigmaDetection from a dict of field→value mappings."""
        return SigmaDetection(
            detection_items=self._make_detection_items(items_dict),
            item_linking=ConditionAND,
        )

    def _make_detection_items(self, items_dict: dict) -> list[SigmaDetectionItem]:
        """Create SigmaDetectionItem list from field→value dict."""
        detection_items = []
        for key, value in items_dict.items():
            if "|" in key:
                field, mod = key.split("|", 1)
                if mod == "contains" and isinstance(value, list):
                    key_attr = f"{field}|contains"
                else:
                    key_attr = key
            else:
                key_attr = key

            try:
                item = SigmaDetectionItem.from_mapping(key_attr, value)
                detection_items.append(item)
            except Exception:
                pass
        return detection_items

    def _build_condition_expr(self, selections: dict) -> str:
        """Build a Sigma condition expression from selection names."""
        names = list(selections.keys())
        if not names:
            return ""

        if len(names) == 1:
            return names[0]

        # Separate positive selections from filter (negated) selections
        pos = [n for n in names if not n.startswith("filter_")]
        neg = [n for n in names if n.startswith("filter_")]

        if pos and neg:
            pos_expr = " and ".join(pos) if len(pos) > 1 else pos[0]
            neg_expr = " and ".join(neg) if len(neg) > 1 else neg[0]
            return f"({pos_expr}) and not ({neg_expr})"
        elif pos:
            return " and ".join(pos) if len(pos) > 1 else pos[0]
        else:
            # All negated — unusual
            return f"not ({' and '.join(neg)})"

    def _build_rule(
        self,
        detection_yaml: dict,
        logsource: SigmaLogSource,
        selections: dict,
        condition_expr: list[str],
    ) -> SigmaRule:
        """Build a full SigmaRule object."""

        # Parse ID as UUID
        rule_id = None
        id_str = detection_yaml.get("id", "")
        if id_str:
            try:
                rule_id = uuid.UUID(id_str)
            except (ValueError, AttributeError):
                pass

        # Parse date
        creation_date = None
        date_str = detection_yaml.get("creation_date", "")
        if date_str:
            try:
                creation_date = datetime.datetime.strptime(
                    str(date_str).split("T")[0], "%Y-%m-%d"
                ).date()
            except (ValueError, Exception):
                pass

        # Map status
        status_map = {
            "experimental": SigmaStatus.EXPERIMENTAL,
            "production": SigmaStatus.STABLE,
            "deprecated": SigmaStatus.DEPRECATED,
            "test": SigmaStatus.TEST,
        }
        status = status_map.get(
            detection_yaml.get("status", "experimental"),
            SigmaStatus.EXPERIMENTAL,
        )

        # Map MITRE ATT&CK tags
        tags = []
        mitre_ids = detection_yaml.get("mitre_attack_id", [])
        if isinstance(mitre_ids, list):
            for tid in mitre_ids:
                if tid and isinstance(tid, str):
                    tags.append(SigmaRuleTag.from_str(f"attack.{tid.replace('.', '_')}"))

        # Map finding score to level
        finding = detection_yaml.get("finding", {})
        if isinstance(finding, dict):
            score = finding.get("entity", {}).get("score", 50)
            if isinstance(score, dict):
                score = 50
        else:
            score = 50
        if score >= 80:
            level = SigmaLevel.CRITICAL
        elif score >= 60:
            level = SigmaLevel.HIGH
        elif score >= 40:
            level = SigmaLevel.MEDIUM
        else:
            level = SigmaLevel.LOW

        # Build the rule
        rule = SigmaRule(
            title=str(detection_yaml.get("name", "Unknown Detection")),
            id=rule_id,
            status=status,
            description=str(detection_yaml.get("description", "")),
            references=list(detection_yaml.get("references", []) or []),
            author=str(detection_yaml.get("author", "")),
            date=creation_date,
            level=level,
            tags=tags,
            logsource=logsource,
            detection=SigmaDetections(
                detections=selections,
                condition=condition_expr,
            ),
        )

        return rule

    # -----------------------------------------------------------------------
    # SigmaHQ directory structure mapping
    # -----------------------------------------------------------------------
    # Top-level dirs: windows, linux, macos, cloud, network, web, identity, application

    # Map (product, category, service) → SigmaHQ subdirectory path
    _PATH_MAP: dict[tuple[str, str, str], str] = {
        # === Windows ===
        ("windows", "process_creation", ""): "windows/process_creation",
        ("windows", "registry_event", ""): "windows/registry/registry_event",
        ("windows", "registry", ""): "windows/registry/registry_event",
        ("windows", "file_event", ""): "windows/file",
        ("windows", "file", ""): "windows/file",
        ("windows", "image_load", ""): "windows/image_load",
        ("windows", "network_connection", ""): "windows/network_connection",
        ("windows", "driver_load", ""): "windows/driver_load",
        ("windows", "create_remote_thread", ""): "windows/create_remote_thread",
        ("windows", "process_access", ""): "windows/process_access",
        ("windows", "pipe_created", ""): "windows/pipe_created",
        ("windows", "dns_query", ""): "windows/dns_query",
        ("windows", "wmi", ""): "windows/wmi_event",
        ("windows", "wmi_event", ""): "windows/wmi_event",
        ("windows", "powershell", ""): "windows/powershell",
        ("windows", "sysmon", ""): "windows/sysmon",
        ("windows", "process_tampering", ""): "windows/process_tampering",
        # Windows builtin event logs
        ("windows", "", "security"): "windows/builtin/security",
        ("windows", "", "system"): "windows/builtin/system",
        ("windows", "", "application"): "windows/builtin/application",
        ("windows", "", "taskscheduler"): "windows/builtin/taskscheduler",
        ("windows", "", "applocker"): "windows/applocker",
        ("windows", "", "ntlm"): "windows/builtin/ntlm",
        ("windows", "", "defender"): "windows/builtin/defender",
        ("windows", "", "appxdeployment"): "windows/builtin/appxdeployment_server",
        ("windows", "", "capi2"): "windows/builtin/capi2",
        ("windows", "", "certificateservices"): "windows/builtin/certificate_service_client",
        ("windows", "", "terminalservices"): "windows/builtin/terminalservices",
        ("windows", "", "printservice"): "windows/builtin/printservice",
        ("windows", "", "active_directory"): "windows/builtin/active_directory",
        # Default windows fallback
        ("windows", "", ""): "windows/process_creation",

        # === Linux ===
        ("linux", "process_creation", ""): "linux/process_creation",
        ("linux", "file_event", ""): "linux/file_event",
        ("linux", "network_connection", ""): "linux/network_connection",
        ("linux", "", "auditd"): "linux/auditd",
        ("linux", "", ""): "linux/process_creation",

        # === macOS ===
        ("macos", "process_creation", ""): "macos/process_creation",
        ("macos", "file_event", ""): "macos/file_event",
        ("macos", "", ""): "macos/process_creation",

        # === Cloud: AWS ===
        ("aws", "", "cloudtrail"): "cloud/aws/cloudtrail",
        ("aws", "", "securitylake"): "cloud/aws/securitylake",
        ("aws", "", "securityhub"): "cloud/aws/securityhub",
        ("aws", "", "vpcflow"): "cloud/aws/vpcflow",
        ("aws", "", "s3access"): "cloud/aws/s3",
        ("aws", "", "eks"): "cloud/aws/eks",
        ("aws", "", ""): "cloud/aws",

        # === Cloud: Azure ===
        ("azure", "", "audit"): "cloud/azure",
        ("azure", "", "aad"): "cloud/azure",
        ("azure", "", "activity"): "cloud/azure",
        ("azure", "", ""): "cloud/azure",

        # === Cloud: GCP ===
        ("gcp", "", "pubsub"): "cloud/gcp",
        ("gcp", "", ""): "cloud/gcp",

        # === Cloud: M365 ===
        ("m365", "", "graph_api"): "cloud/m365",
        ("m365", "", "management"): "cloud/m365",
        ("m365", "", "defender"): "cloud/m365",
        ("m365", "", "exchange"): "cloud/m365",
        ("m365", "", ""): "cloud/m365",

        # === Cloud: Google Workspace ===
        ("google_workspace", "", ""): "cloud/gcp",

        # === Identity ===
        ("okta", "", "okta"): "identity/okta",
        ("okta", "", ""): "identity/okta",
        ("cisco", "", "duo"): "identity/cisco_duo",

        # === Network ===
        ("", "dns", ""): "network/dns",
        ("", "network_connection", ""): "network",
        ("", "firewall", ""): "network/firewall",
        ("", "authentication", ""): "network",
        ("cisco", "", "asa"): "network/cisco",
        ("cisco", "", "ios"): "network/cisco",
        ("cisco", "", "firewall"): "network/cisco",
        ("zeek", "", ""): "network/zeek",
        ("suricata", "", "ids"): "network/suricata",

        # === Web ===
        ("", "webserver", ""): "web/webserver_generic",
        ("", "proxy", ""): "web/proxy_generic",
        ("", "web", ""): "web/webserver_generic",

        # === Application ===
        ("github", "", ""): "application/github",
        ("splunk", "", ""): "application/splunk",
        ("kubernetes", "", ""): "application/kubernetes",
        ("circleci", "", ""): "application/ci_cd",
        ("", "application", ""): "application",

        # === Others ===
        ("", "", "crowdstrike"): "application/crowdstrike",
        ("", "", "carbonblack"): "application/carbonblack",
        ("", "", "osquery"): "application/osquery",
        ("", "all_traffic", ""): "network",
        ("", "network_traffic", ""): "network",
        ("", "certificates", ""): "network",
        ("", "all_certificates", ""): "network",
        ("", "email", ""): "cloud/m365",
        ("", "all_email", ""): "cloud/m365",
        ("cisco", "", ""): "network/cisco",
        ("", "process_creation", ""): "windows/process_creation",
    }

    def _get_output_path(
        self, output_dir: str, rule: SigmaRule, detection_yaml: dict
    ) -> str:
        """Determine the output file path matching SigmaHQ's conventions."""
        ls = rule.logsource
        product = (ls.product or "").lower()
        category = (ls.category or "").lower()
        service = (ls.service or "").lower()

        # Try exact match first, then progressively looser
        path = None
        for keys in [
            (product, category, service),
            (product, category, ""),
            (product, "", service),
            (product, "", ""),
            ("", category, ""),
            ("", "", service),
        ]:
            path = self._PATH_MAP.get(keys)
            if path:
                break

        if not path:
            path = "other"

        # Build clean slug from rule title (preserves original name, no prefix)
        title = rule.title or "unknown"
        slug = title.lower()
        slug = slug.replace(" ", "_").replace("/", "_").replace("\\", "_")
        slug = "".join(c if c.isalnum() or c in "_-" else "" for c in slug)
        slug = slug.strip("_")[:100]

        filename = f"{slug}.yml"
        return os.path.join(output_dir, path, filename)
