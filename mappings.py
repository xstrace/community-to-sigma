"""
Field and Logsource Mappings: Splunk CIM → Sigma Standard Fields.

Maps Splunk Common Information Model (CIM) data model fields and data source
indicators to Sigma standard field names and logsource definitions.
"""

# ---------------------------------------------------------------------------
# CIM FIELD NAME → SIGMA FIELD NAME
# ---------------------------------------------------------------------------
CIM_FIELD_MAP: dict[str, str] = {
    # Endpoint.Processes
    "Processes.process": "CommandLine",
    "Processes.process_name": "Image",
    "Processes.process_path": "Image",
    "Processes.original_file_name": "OriginalFileName",
    "Processes.parent_process": "ParentCommandLine",
    "Processes.parent_process_name": "ParentImage",
    "Processes.parent_process_path": "ParentImage",
    "Processes.parent_process_exec": "ParentImage",
    "Processes.process_exec": "Image",
    "Processes.process_guid": "ProcessGuid",
    "Processes.parent_process_guid": "ParentProcessGuid",
    "Processes.process_id": "ProcessId",
    "Processes.parent_process_id": "ParentProcessId",
    "Processes.process_hash": "Hashes",
    "Processes.process_integrity_level": "IntegrityLevel",
    "Processes.user": "User",
    "Processes.user_id": "User",
    "Processes.dest": "Computer",
    "Processes.vendor_product": "Product",

    # Endpoint.Registry
    "Registry.registry_path": "TargetObject",
    "Registry.registry_key_name": "TargetObject",
    "Registry.registry_value_data": "Details",
    "Registry.registry_value_name": "Details",
    "Registry.registry_value_type": "EventType",
    "Registry.registry_hive": "TargetObject",
    "Registry.process_guid": "ProcessGuid",
    "Registry.process_id": "ProcessId",
    "Registry.status": "EventType",
    "Registry.user": "User",
    "Registry.dest": "Computer",
    "Registry.vendor_product": "Product",

    # Endpoint.Filesystem
    "Filesystem.file_path": "TargetFilename",
    "Filesystem.file_name": "Image",
    "Filesystem.file_hash": "Hashes",
    "Filesystem.dest": "Computer",
    "Filesystem.user": "User",

    # Web
    "Web.url": "cs-uri",
    "Web.uri": "cs-uri",
    "Web.http_method": "cs-method",
    "Web.status": "sc-status",
    "Web.src": "c-ip",
    "Web.dest": "s-ip",
    "Web.http_user_agent": "cs-user-agent",
    "Web.http_referrer": "cs-referrer",
    "Web.vendor_product": "Product",

    # Network_Resolution / DNS
    "DNS.query": "QueryName",
    "DNS.answer": "QueryResults",
    "DNS.src": "Computer",
    "DNS.dest": "Computer",

    # Authentication
    "Authentication.user": "User",
    "Authentication.src": "SrcHost",
    "Authentication.dest": "TargetHost",
    "Authentication.app": "Application",
    "Authentication.action": "EventType",

    # Change
    "All_Changes.command": "CommandLine",
    "All_Changes.user": "User",
    "All_Changes.dest": "Computer",
    "All_Changes.result": "Result",
}

# Common field aliases (Splunk → Sigma)
COMMON_FIELD_ALIASES: dict[str, str] = {
    # Windows Event Log
    "EventCode": "EventID",
    "EventID": "EventID",
    "Computer": "Computer",
    "ComputerName": "Computer",

    # Process/parent fields (non data-model)
    "process_name": "Image",
    "parent_process_name": "ParentImage",
    "process": "CommandLine",
    "parent_process": "ParentCommandLine",
    "process_path": "Image",
    "parent_process_path": "ParentImage",
    "Image": "Image",
    "ParentImage": "ParentImage",
    "CommandLine": "CommandLine",
    "ParentCommandLine": "ParentCommandLine",
    "ProcessGuid": "ProcessGuid",
    "ParentProcessGuid": "ParentProcessGuid",

    # PowerShell
    "ScriptBlockText": "ScriptBlockText",
    "Path": "Image",
    "ProcessID": "ProcessId",

    # Sysmon
    "ImageLoaded": "ImageLoaded",
    "TargetFilename": "TargetFilename",
    "TargetObject": "TargetObject",
    "Details": "Details",
    "Signed": "Signed",
    "Signature": "Signature",
    "ServiceName": "ServiceName",
    "ServiceFileName": "ServiceFileName",

    # CloudTrail
    "eventName": "eventName",
    "eventSource": "eventSource",
    "userName": "userIdentity.userName",
    "user_arn": "userIdentity.arn",
    "src": "src",
    "dest": "dest",
    "user": "User",
    "errorMessage": "errorMessage",
    "additionalEventData.MFAUsed": "additionalEventData.MFAUsed",

    # Web
    "url": "url",
    "uri": "cs-uri",
    "http_method": "cs-method",
    "status": "sc-status",
    "http_user_agent": "cs-user-agent",

    # Identity
    "user_name": "User",
    "src_user": "SrcUser",
    "TargetUserName": "TargetUserName",
    "SubjectUserName": "SubjectUserName",
    "ObjectClass": "ObjectClass",
    "ObjectDN": "ObjectDN",

    # Network
    "dest_ip": "DestinationIp",
    "src_ip": "SourceIp",
    "dest_port": "DestinationPort",
    "src_port": "SourcePort",
    "protocol": "Protocol",
    "query": "QueryName",
    "answer": "QueryResults",

    # Generic
    "vendor_product": "Product",
    "signature": "Signature",
    "signature_id": "SignatureId",
    "severity": "severity",
}

# ---------------------------------------------------------------------------
# DATA SOURCE → SIGMA LOGSOURCE MAPPING
# ---------------------------------------------------------------------------

# Mapping from Splunk CIM data model to Sigma logsource
DATAMODEL_LOGSOURCE_MAP: dict[str, dict[str, str]] = {
    "Endpoint.Processes": {
        "product": "windows",
        "category": "process_creation",
    },
    "Endpoint.Registry": {
        "product": "windows",
        "category": "registry_event",
    },
    "Endpoint.Filesystem": {
        "product": "windows",
        "category": "file_event",
    },
    "Endpoint.Ports": {
        "product": "windows",
        "category": "network_connection",
    },
    "Endpoint.Services": {
        "product": "windows",
        "category": "process_creation",
    },
    "Web": {
        "category": "webserver",
    },
    "Network_Resolution": {
        "category": "dns",
    },
    "Network_Traffic": {
        "category": "network_connection",
    },
    "Network_Sessions": {
        "category": "network_connection",
    },
    "Authentication": {
        "category": "authentication",
    },
    "Change.All_Changes": {
        "category": "process_creation",
    },
    "Change": {
        "category": "process_creation",
    },
}

# Mapping from Splunk data source (macro-based) to Sigma logsource
MACRO_LOGSOURCE_MAP: dict[str, dict[str, str]] = {
    # Windows event sources
    "sysmon": {"product": "windows", "service": "sysmon"},
    "wineventlog_security": {"product": "windows", "service": "security"},
    "wineventlog_system": {"product": "windows", "service": "system"},
    "wineventlog_application": {"product": "windows", "service": "application"},
    "powershell": {"product": "windows", "service": "powershell"},
    "ms_defender": {"product": "windows", "service": "defender"},
    "applocker": {"product": "windows", "service": "applocker"},
    "wineventlog_task_scheduler": {"product": "windows", "service": "taskscheduler"},
    "wineventlog_rdp": {"product": "windows", "service": "terminalservices"},
    "wmi": {"product": "windows", "service": "wmi"},
    "ntlm_audit": {"product": "windows", "service": "ntlm"},
    "printservice": {"product": "windows", "service": "printservice-admin"},
    "remoteconnectionmanager": {"product": "windows", "service": "terminalservices"},
    "capi2_operational": {"product": "windows", "service": "capi2"},
    "certificateservices_lifecycle": {"product": "windows", "service": "certificateservices"},

    # AWS
    "cloudtrail": {"product": "aws", "service": "cloudtrail"},
    "amazon_security_lake": {"product": "aws", "service": "securitylake"},
    "aws_cloudwatchlogs_eks": {"product": "aws", "service": "eks"},
    "aws_cloudwatchlogs_vpcflow": {"product": "aws", "service": "vpcflow"},
    "aws_s3_accesslogs": {"product": "aws", "service": "s3access"},
    "aws_securityhub_finding": {"product": "aws", "service": "securityhub"},
    "cloudwatchlogs_vpcflow": {"product": "aws", "service": "vpcflow"},

    # Azure
    "azure_audit": {"product": "azure", "service": "audit"},
    "azure_monitor_aad": {"product": "azure", "service": "aad"},
    "azure_monitor_activity": {"product": "azure", "service": "activity"},

    # Google
    "gsuite_calendar": {"product": "google_workspace", "service": "calendar"},
    "gsuite_drive": {"product": "google_workspace", "service": "drive"},
    "gsuite_gmail": {"product": "google_workspace", "service": "gmail"},
    "gws_reports_admin": {"product": "google_workspace", "service": "admin"},
    "gws_reports_login": {"product": "google_workspace", "service": "login"},
    "google_gcp_pubsub_message": {"product": "gcp", "service": "pubsub"},

    # M365
    "o365_graph": {"product": "m365", "service": "graph_api"},
    "o365_management_activity": {"product": "m365", "service": "management"},
    "ms365_defender_incident_alerts": {"product": "m365", "service": "defender"},
    "ms_defender_atp_alerts": {"product": "m365", "service": "defender"},
    "msexchange_management": {"product": "m365", "service": "exchange"},
    "github_organizations": {"product": "github", "service": "audit"},

    # Okta
    "okta": {"product": "okta", "service": "okta"},

    # Cisco
    "cisco_asa": {"product": "cisco", "service": "asa"},
    "cisco_ios": {"product": "cisco", "service": "ios"},
    "cisco_networks": {"product": "cisco", "service": "ios"},
    "cisco_secure_firewall": {"product": "cisco", "service": "firewall"},
    "cisco_duo_activity": {"product": "cisco", "service": "duo"},
    "cisco_duo_administrator": {"product": "cisco", "service": "duo"},

    # Zeek / Suricata
    "zeek_ssl": {"product": "zeek", "service": "ssl"},
    "zeek_rpc": {"product": "zeek", "service": "rpc"},
    "zeek_x509": {"product": "zeek", "service": "x509"},
    "stream_http": {"product": "zeek", "service": "http"},
    "stream_dns": {"product": "zeek", "service": "dns"},
    "stream_tcp": {"product": "zeek", "service": "tcp"},
    "suricata": {"product": "suricata", "service": "ids"},

    # Others
    "splunkd": {"product": "splunk", "service": "splunkd"},
    "kubernetes": {"category": "kubernetes"},
    "osquery": {"service": "osquery"},
    "github_enterprise": {"product": "github", "service": "enterprise"},
    "crowdstrike_stream": {"service": "crowdstrike"},
    "crowdstrike_identities": {"service": "crowdstrike"},
    "carbonblack": {"service": "carbonblack"},
    "linux_auditd": {"service": "auditd"},
    "linux_hosts": {"service": "linux"},
    "admon": {"product": "windows", "service": "active_directory"},
    "risk_index": {"category": "any"},  # risk index is meta, shouldn't be converted

    # Application-specific
    "circleci": {"service": "circleci", "category": "application"},
    "nginx_access_logs": {"service": "nginx", "category": "webserver"},
    "zscaler_proxy": {"service": "zscaler", "category": "proxy"},
}

# ---------------------------------------------------------------------------
# MAPPING HELPERS
# ---------------------------------------------------------------------------

def map_cim_field(field_name: str) -> str:
    """Map a Splunk CIM field name to a Sigma field name.

    Strips the data model prefix (e.g., Processes.X → X) and applies mappings.
    Falls back to the original field name if no mapping exists.
    """
    # Check exact match in CIM field map
    if field_name in CIM_FIELD_MAP:
        return CIM_FIELD_MAP[field_name]

    # Strip data model prefix: Datamodel.field → field
    if "." in field_name:
        parts = field_name.split(".", 1)
        if len(parts) == 2:
            field_name = parts[1]

    # Check common aliases
    if field_name in COMMON_FIELD_ALIASES:
        return COMMON_FIELD_ALIASES[field_name]

    # Return as-is
    return field_name


def map_datamodel_to_logsource(datamodel_name: str) -> dict:
    """Map a Splunk CIM data model name to Sigma logsource fields."""
    if datamodel_name in DATAMODEL_LOGSOURCE_MAP:
        return dict(DATAMODEL_LOGSOURCE_MAP[datamodel_name])
    return {"category": datamodel_name.lower()}


def map_macro_to_logsource(macro_name: str) -> dict | None:
    """Map a Splunk data source macro to Sigma logsource fields."""
    name = macro_name.strip("`")
    return MACRO_LOGSOURCE_MAP.get(name)
