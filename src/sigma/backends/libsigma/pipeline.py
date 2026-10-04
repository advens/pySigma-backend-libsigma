# SPDX-License-Identifier: LGPL-2.1-only
"""Sigma-taxonomy to ECS field rename.

SigmaHQ rules use the Sigma field names (``Image``, ``src_ip``, ``QueryName``).
libsigma compares those names to the strings the host field callback returns.
When the callback returns ECS names (``process.executable``, ``source.ip``,
``dns.question.name``), the rule has to be renamed before it is compiled or it
will not match.

``ecs_pipeline()`` is that rename. It is logsource-gated: a ``process_creation``
rule maps ``Image`` to ``process.executable``; a ``firewall`` rule maps
``src_ip`` to ``source.ip``. It does not decide whether a deployment actually
produces the ECS field. A name with no row stays as written. A caller
that already stores Sigma names leaves the pipeline off (``ecs=False``)
and the compiler emits the names as written.

Taxonomy (Sigma v2 ``taxonomy:``):

* absent or ``sigma``: apply the maps.
* ``ecs``: the YAML already uses ECS names, so the maps are not applied.
* anything else: compile error for that rule.
"""

from __future__ import annotations

from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from sigma.processing.conditions import LogsourceCondition


# --- per-logsource field maps (Sigma field -> ECS field) -------------------
_FIREWALL = {
    "src_ip": "source.ip", "dst_ip": "destination.ip",
    "src_port": "source.port", "dst_port": "destination.port",
    "protocol": "network.transport", "action": "event.action",
    # Sigma / iptables / Zeek spellings that land on fields we emit.
    "srcip": "source.ip", "dstip": "destination.ip",
    "SourceIP": "source.ip", "DestinationIP": "destination.ip",
    "source_port": "source.port", "dest_port": "destination.port",
    "srcport": "source.port", "dstport": "destination.port",
    "sport": "source.port", "dport": "destination.port",
    "spt": "source.port", "dpt": "destination.port",
    "destination_port": "destination.port",
}

_NETWORK_CONNECTION = {
    "SourceIp": "source.ip", "DestinationIp": "destination.ip",
    "SourceIP": "source.ip", "DestinationIP": "destination.ip",
    "SourcePort": "source.port", "DestinationPort": "destination.port",
    "Protocol": "network.transport", "DestinationHostname": "destination.domain",
    "SourceHostname": "source.domain",
    "Image": "process.executable", "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable", "User": "user.name",
}

_PROCESS_CREATION = {
    "Image": "process.executable", "OriginalFileName": "process.pe.original_file_name",
    "CommandLine": "process.command_line", "CurrentDirectory": "process.working_directory",
    "ParentImage": "process.parent.executable", "ParentCommandLine": "process.parent.command_line",
    "User": "user.name", "ProcessId": "process.pid", "ParentProcessId": "process.parent.pid",
    "IntegrityLevel": "process.integrity_level", "Hashes": "process.hash",
    # PE metadata emitted for an endpoint process.
    "Description": "process.pe.description",
    "Product": "process.pe.product",
    "Company": "process.pe.company",
    "FileVersion": "process.pe.file_version",
    "ProcessGuid": "process.entity_id",
    "ParentProcessGuid": "process.parent.entity_id",
}

_WEBSERVER = {
    "c-ip": "source.ip", "cs-method": "http.request.method",
    "cs-uri-stem": "url.path", "cs-uri-query": "url.query", "cs-uri": "url.original",
    "sc-status": "http.response.status_code",
    "c-useragent": "user_agent.original", "cs-user-agent": "user_agent.original",
    "cs-host": "url.domain", "cs-referer": "http.request.referrer",
    "sni": "tls.client.server_name",
}

_PROXY = {
    "src_ip": "source.ip", "dst_ip": "destination.ip",
    "c-uri": "url.original", "cs-uri": "url.original",
    "c-uri-extension": "url.extension", "c-uri-query": "url.query",
    "cs-method": "http.request.method", "cs-host": "url.domain",
    "c-useragent": "user_agent.original", "cs-user-agent": "user_agent.original",
    "sc-status": "http.response.status_code",
    "cs-bytes": "http.request.bytes", "sc-bytes": "http.response.bytes",
    "sni": "tls.client.server_name",
}

_LINUX = {
    "User": "user.name",
    "ComputerName": "host.name",
    "hostname": "host.name",
}

# DNS. SigmaHQ uses two shapes:
#   Sysmon dns_query: QueryName, query, record_type, Image, User
#   resolver / Zeek: query, record_type, qtype_name, src_ip, id.orig_h
# Answer and result fields have no row here; they stay as written.
_DNS = {
    "QueryName": "dns.question.name",
    "query": "dns.question.name",
    "parent_domain": "dns.question.name",
    "record_type": "dns.question.type",
    "qtype_name": "dns.question.type",
    "QueryClass": "dns.question.class",
    "src_ip": "source.ip",
    "SourceIp": "source.ip",
    "id.orig_h": "source.ip",
    "id.resp_h": "destination.ip",
    "qname": "dns.question.name",
    "dns_query": "dns.question.name",
    "Image": "process.executable",
    "User": "user.name",
}

# Linux SSH / auth. SigmaHQ sshd and authentication rules use these names.
_LINUX_AUTH = {
    "User": "user.name",
    "user": "user.name",
    "Source": "source.ip",
    "SourceIP": "source.ip",
    "SourceIp": "source.ip",
    "src_ip": "source.ip",
    "SourcePort": "source.port",
    "src_port": "source.port",
    "port": "source.port",
    "pid": "process.pid",
    # sudo / audit: COMMAND and PWD are the common SigmaHQ linux names.
    "Command": "process.command_line",
    "COMMAND": "process.command_line",
    "command": "process.command_line",
    "cmdline": "process.command_line",
    "command_line": "process.command_line",
    "PWD": "process.working_directory",
    "CWD": "process.working_directory",
    "ComputerName": "host.name",
    "hostname": "host.name",
}

# Mail / SMTP. SigmaHQ sender, recipient, account, and client-IP names.
_MAIL = {
    "User": "user.name",
    "AccountName": "user.name",
    "Source": "source.ip",
    "SourceIp": "source.ip",
    "src_ip": "source.ip",
    "SourcePort": "source.port",
    "DestinationPort": "destination.port",
    "Protocol": "network.protocol",
    "sender": "source.user.email",
    "from": "source.user.email",
    "MailFrom": "source.user.email",
    "recipient": "destination.user.email",
    "to": "destination.user.email",
    "RcptTo": "destination.user.email",
}

# File, image, and registry categories. A Sysmon spelling with no row
# (Signed, Imphash, TargetImage, ScriptBlockText) stays written.
# Initiated is not renamed: Sigma stores true/false and network.direction
# is a word, so a rename alone would not match.
_FILE_EVENT = {
    "TargetFilename": "file.path",
    "Image": "process.executable",
    "CommandLine": "process.command_line",
    "ParentImage": "process.parent.executable",
    "User": "user.name",
    "ProcessId": "process.pid",
    "ProcessGuid": "process.entity_id",
}

_IMAGE_LOAD = {
    "Image": "process.executable",
    "ImageLoaded": "file.path",
    "Product": "file.pe.product",
    "Company": "file.pe.company",
    "FileVersion": "file.pe.file_version",
    "User": "user.name",
    "ProcessId": "process.pid",
    "ProcessGuid": "process.entity_id",
}

_REGISTRY = {
    "TargetObject": "registry.path",
    "Details": "registry.data.strings",
    "Image": "process.executable",
    "User": "user.name",
    "ProcessId": "process.pid",
    "ProcessGuid": "process.entity_id",
}

_PROCESS_ACCESS = {
    "SourceImage": "process.executable",
    "SourceProcessId": "process.pid",
    "User": "user.name",
}

_PIPE = {
    "PipeName": "file.name",
    "Image": "process.executable",
}

# A category condition matches that category only. Product and service are
# separate conditions below.
_MAPS = {
    "firewall": _FIREWALL,
    "network_connection": _NETWORK_CONNECTION,
    "process_creation": _PROCESS_CREATION,
    "webserver": _WEBSERVER,
    "proxy": _PROXY,
    "dns": _DNS,
    "dns_query": _DNS,
    "authentication": _LINUX_AUTH,
    "file_event": _FILE_EVENT,
    "file_delete": _FILE_EVENT,
    "file_change": _FILE_EVENT,
    "file_delete_detected": _FILE_EVENT,
    "create_stream_hash": _FILE_EVENT,
    "image_load": _IMAGE_LOAD,
    "driver_load": _IMAGE_LOAD,
    "registry_event": _REGISTRY,
    "registry_add": _REGISTRY,
    "registry_delete": _REGISTRY,
    "registry_set": _REGISTRY,
    "registry_rename": _REGISTRY,
    "process_access": _PROCESS_ACCESS,
    "create_remote_thread": _PROCESS_ACCESS,
    "pipe_created": _PIPE,
}

# service-gated maps: SigmaHQ ships SSH/auth rules under logsource.service
# (no category), so these must be matched on the service token.
_SERVICE_MAPS = {
    "sshd": _LINUX_AUTH,
    "auth": _LINUX_AUTH,
    "sudo": _LINUX_AUTH,
    "dns": _DNS,
    "smtp": _MAIL,
    "mail": _MAIL,
}

# Windows Security channel. Subject* is the actor. TargetUserName stays
# written: ECS has one user.name, and folding the target into it would
# compare the rule to the wrong account. ServiceFileName and ObjectName
# have no row.
_WINDOWS_SECURITY = {
    "EventID": "event.code",
    "ComputerName": "host.name",
    "SubjectUserName": "user.name",
    "SubjectDomainName": "user.domain",
    "SubjectUserSid": "user.id",
    "ProcessName": "process.executable",
    "NewProcessName": "process.executable",
    "ParentProcessName": "process.parent.name",
    "CommandLine": "process.command_line",
    "IpAddress": "source.ip",
    "IpPort": "source.port",
    "WorkstationName": "source.domain",
    "Application": "process.executable",
    "ServiceName": "service.name",
}

_WINDOWS_EVENT = {
    "EventID": "event.code",
    "ComputerName": "host.name",
}

# CloudTrail field names.
_CLOUDTRAIL = {
    "eventName": "event.action",
    "eventSource": "event.provider",
    "sourceIPAddress": "source.ip",
    "userAgent": "user_agent.original",
}

# Azure AD audit names. Activity logs keep operationName: that source
# writes a vendor field, not event.action.
_AZURE_AUDIT = {
    "operationName": "event.action",
    "OperationName": "event.action",
}

# auditd exe and comm. a0, SYSCALL, and type have no row.
_AUDITD = {
    "exe": "process.executable",
    "comm": "process.name",
}

# (product, service, mapping). Both tokens are required, so a linux rule
# does not pick up the Windows Security table.
_PRODUCT_SERVICE_MAPS = (
    ("windows", "security", _WINDOWS_SECURITY),
    ("windows", "system", _WINDOWS_EVENT),
    ("windows", "application", _WINDOWS_EVENT),
    ("aws", "cloudtrail", _CLOUDTRAIL),
    ("azure", "auditlogs", _AZURE_AUDIT),
    ("linux", "auditd", _AUDITD),
)


def _all_maps():
    """Every field table the pipeline installs, category then service then product."""
    yield from _MAPS.values()
    yield from _SERVICE_MAPS.values()
    yield _LINUX
    for _product, _service, mapping in _PRODUCT_SERVICE_MAPS:
        yield mapping


# Sigma-side names the maps consume. Used to tell an ecs-taxonomy rule that
# leaked a Sigma spelling (``dst_ip``) from a field we simply do not have.
SIGMA_FIELD_NAMES: frozenset[str] = frozenset(
    key for mapping in _all_maps() for key in mapping
)


# Sigma v2 taxonomies this pipeline understands. Default (absent) is ``sigma``.
SUPPORTED_TAXONOMIES = frozenset({"sigma", "ecs"})


class TaxonomyError(ValueError):
    """Rule declared a taxonomy this compiler does not accept."""


def normalize_taxonomy(value) -> str:
    """Lower-case taxonomy token; empty / missing -> ``sigma`` (spec default)."""
    if value is None:
        return "sigma"
    token = str(value).strip().lower()
    return token or "sigma"


def rule_taxonomy(rule) -> str:
    """Resolved taxonomy of a parsed pySigma rule (default ``sigma``)."""
    return normalize_taxonomy(getattr(rule, "taxonomy", None))


def apply_rule_taxonomy(rule, pipe: ProcessingPipeline) -> str:
    """Apply the Sigma->ECS map only when the YAML is ``taxonomy: sigma``.

    Returns the resolved taxonomy. A value other than ``sigma`` or ``ecs``
    raises ``TaxonomyError``. The compiler records that as a rule error.
    """
    tax = rule_taxonomy(rule)
    if tax not in SUPPORTED_TAXONOMIES:
        raise TaxonomyError(
            f"unsupported taxonomy {tax!r} (accepted: sigma, ecs)"
        )
    if tax == "sigma":
        pipe.apply(rule)
    return tax


def unmapped_drop_reason(unmapped: list[str], taxonomy: str) -> str:
    """Human reason for an unmapped-field drop; names Sigma leaks on ecs rules."""
    leak = sorted(f for f in unmapped if f in SIGMA_FIELD_NAMES)
    if taxonomy == "ecs" and leak:
        extra = sorted(set(unmapped) - set(leak))
        reason = f"taxonomy ecs but Sigma field(s) {leak}"
        if extra:
            reason += f"; unmapped field(s) {extra}"
        return reason + " (write the ECS name, or omit taxonomy to map)"
    return f"not relevant: unmapped field(s) {unmapped}"


def ecs_pipeline() -> ProcessingPipeline:
    """Sigma field names to ECS, gated by logsource category, service, or product."""
    items = [
        ProcessingItem(
            identifier=f"libsigma_ecs_{category}",
            transformation=FieldMappingTransformation(mapping),
            rule_conditions=[LogsourceCondition(category=category)],
        )
        for category, mapping in _MAPS.items()
    ]
    # service-gated families (sshd/auth/smtp/mail/dns carry no Sigma category)
    items.extend(
        ProcessingItem(
            identifier=f"libsigma_ecs_service_{service}",
            transformation=FieldMappingTransformation(mapping),
            rule_conditions=[LogsourceCondition(service=service)],
        )
        for service, mapping in _SERVICE_MAPS.items()
    )
    # generic linux (product-gated) for sources without a specific category map
    items.append(
        ProcessingItem(
            identifier="libsigma_ecs_linux",
            transformation=FieldMappingTransformation(_LINUX),
            rule_conditions=[LogsourceCondition(product="linux")],
        )
    )
    items.extend(
        ProcessingItem(
            identifier=f"libsigma_ecs_{product}_{service}",
            transformation=FieldMappingTransformation(mapping),
            rule_conditions=[LogsourceCondition(product=product, service=service)],
        )
        for product, service, mapping in _PRODUCT_SERVICE_MAPS
    )
    return ProcessingPipeline(name="libsigma-ecs", priority=20, items=items)



def corr_field_to_ecs(name: str, *, map_fields: bool = True) -> str:
    """Map a correlation group-by field through the same tables.

    ``map_fields=False`` (taxonomy ``ecs``) leaves the name as written.
    A name with no row stays as written. This function does not drop fields.
    """
    if not name or not map_fields:
        return name
    for mapping in _all_maps():
        mapped = mapping.get(name)
        if mapped:
            return mapped
    return name
