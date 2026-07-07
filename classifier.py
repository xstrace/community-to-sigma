"""
Detection Classifier.

Determines whether a Splunk detection rule is convertible to Sigma
or should be skipped based on SPL features present in the parsed AST.

Key principle: if the FIRST stage (tstats/search) has clean single-event
matching conditions, the rule is convertible. Complex processing in later
stages (eval, lookup, bucket, bin, stats) is ignored for Sigma purposes
since we only care about the core detection logic.
"""

from macro_resolver import MacroResolver


# Commands that mean the ENTIRE detection is too complex (even if first stage is clean)
# These are commands that fundamentally change the nature of the detection
ALWAYS_COMPLEX_COMMANDS = {
    "transaction",    # multi-event correlation
    "eventstats",     # statistical baseline
    "streamstats",    # streaming statistics
    "timechart",      # time-based charting
    "chart",          # charting
    "inputlookup",    # external lookup for reference
    "outputlookup",   # external write
}

# Commands that DON'T prevent conversion if in later stages (after conditions extracted)
CONDITIONAL_COMMANDS = {
    "bucket",         # time bucketing after search is fine
    "bin",            # time bucketing after search is fine
    "eval",           # eval after search is fine
    "lookup",         # lookup after search is fine (we extract pre-lookup conditions)
    "makemv",         # multi-value expansion after search is fine
}


def classify_detection(ast: dict, macro_resolver: MacroResolver) -> tuple[bool, str, dict]:
    """
    Classify a parsed SPL detection as convertible or skip.

    Returns:
        (is_convertible, skip_reason, extracted_info)
    """
    info = {
        "macros": [],
        "data_model": None,
        "conditions": None,
        "logsource_hints": {},
        "commands": [],
    }

    skip_reasons = []
    stages = ast.get("stages", [])

    # Collect all macros from the AST (both from tree and _macros field)
    _collect_macros(ast, info["macros"])
    for m in ast.get("_macros", []):
        if m not in info["macros"]:
            info["macros"].append(m)

    # Check macros for complexity
    for macro_name in info["macros"]:
        name = macro_name.strip("`")
        if macro_resolver.is_macro_complex(name):
            skip_reasons.append(f"Complex macro: {name}")
        if name in MacroResolver.LOOKUP_MACROS:
            skip_reasons.append(f"Lookup macro: {name}")

    # Extract conditions from the FIRST meaningful stage (tstats or search)
    # Later stages may have complex processing, but we only need the core
    # detection logic from the first stage.
    found_conditions = False
    found_data_model = False

    for stage in stages:
        stage_type = stage.get("type", "")

        if stage_type == "command":
            cmd = stage.get("command", "").lower()
            info["commands"].append(cmd)

            # Always-complex commands prevent conversion entirely
            # Handle unparseable complex queries
            if cmd == "__unparseable_complex__":
                skip_reasons.append("Unparseable SPL with complex patterns")
                break

            # Always-complex commands prevent conversion entirely
            if cmd in ALWAYS_COMPLEX_COMMANDS:
                skip_reasons.append(f"Always-complex command: {cmd}")

            if cmd == "tstats":
                # Extract data model info
                from_refs = stage.get("from", [])
                for ref in from_refs:
                    if isinstance(ref, dict) and ref.get("type") == "datamodel":
                        datamodel_name = ref.get("name", "")
                        info["data_model"] = datamodel_name
                        found_data_model = True
                        if "Risk" in datamodel_name:
                            skip_reasons.append(
                                f"Risk datamodel (meta-correlation): {datamodel_name}"
                            )

                # Extract WHERE conditions (core detection logic)
                where_cond = stage.get("where")
                if where_cond and not found_conditions:
                    # Check if the where clause itself has complex eval
                    if not _condition_has_complex_eval(where_cond):
                        info["conditions"] = where_cond
                        found_conditions = True

                # Collect macros from tstats
                stage_macros = stage.get("macros", [])
                for m in stage_macros:
                    info["macros"].append(m)

            elif cmd == "where":
                where_cond = stage.get("condition")
                if where_cond and not found_conditions:
                    if not _condition_has_complex_eval(where_cond):
                        info["conditions"] = where_cond
                        found_conditions = True

            elif cmd == "search":
                # | search <condition> — extract conditions from explicit search commands
                search_cond = stage.get("condition")
                if search_cond and not found_conditions:
                    if not _condition_has_complex_eval(search_cond):
                        if search_cond.get("type") not in ("macro",):
                            info["conditions"] = search_cond
                            found_conditions = True

            elif cmd == "lookup":
                # lookup after conditions are already extracted is fine
                if not found_conditions:
                    skip_reasons.append("lookup command present before conditions")

        elif stage_type == "search":
            cond = stage.get("condition")
            if cond and not found_conditions:
                # Skip trivial conditions (just a macro reference or utility)
                if cond.get("type") not in ("macro",):
                    if not _condition_has_complex_eval(cond):
                        info["conditions"] = cond
                        found_conditions = True

    # If no conditions found, check why
    if not found_conditions:
        skip_reasons.append("No conditions extracted")

    # Determine logsource hints
    if info["data_model"]:
        info["logsource_hints"]["data_model"] = info["data_model"]

    for macro_name in info["macros"]:
        name = macro_name.strip("`")
        ls_hint = macro_resolver.get_logsource_hint(name)
        if ls_hint:
            info["logsource_hints"]["macro"] = name
            info["logsource_hints"]["macro_info"] = ls_hint
            break

    is_convertible = len(skip_reasons) == 0
    reason = "; ".join(skip_reasons) if skip_reasons else ""

    return is_convertible, reason, info


def _condition_has_complex_eval(node) -> bool:
    """Check if a condition AST contains complex eval (CASE, replace, etc.).
    Only checks the condition tree, not the whole AST."""
    if not isinstance(node, dict):
        return False

    node_type = node.get("type", "")

    if node_type == "function_call":
        func_name = node.get("name", {}).get("raw", "")
        if func_name.lower() in {
            "case", "replace", "split", "mvjoin", "trim", "match",
            "tonumber", "tostring", "urldecode", "mvfilter", "mvindex",
        }:
            return True

    # Recurse
    for key, value in node.items():
        if key == "type":
            continue
        if isinstance(value, dict):
            if _condition_has_complex_eval(value):
                return True
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    if _condition_has_complex_eval(item):
                        return True

    return False


def _collect_macros(node, macros: list[str]):
    """Recursively collect all macro references from the AST."""
    if not isinstance(node, dict):
        return

    if node.get("type") == "macro":
        macros.append(node.get("value", ""))
        return

    for key, value in node.items():
        if key == "type":
            continue
        if isinstance(value, dict):
            _collect_macros(value, macros)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _collect_macros(item, macros)
                elif isinstance(item, str):
                    if item.startswith("`") and item.endswith("`"):
                        macros.append(item)
