# SPDX-License-Identifier: LGPL-2.1-only
"""Compiler and backend behavior that is part of the public contract."""

import struct

import pytest

pytest.importorskip("sigma")

from sigma.backends.libsigma import LibsigmaBackend  # noqa: E402
from sigma.backends.libsigma.compiler import compile_rules  # noqa: E402
from sigma.backends.libsigma.format import MAGIC  # noqa: E402
from sigma.backends.libsigma.pipeline import apply_rule_taxonomy, ecs_pipeline  # noqa: E402
from sigma.collection import SigmaCollection  # noqa: E402


_PROCESS = """
title: Encoded PowerShell
id: aaaaaaaa-0000-0000-0000-000000000001
level: high
tags:
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\powershell.exe'
  condition: sel
"""

_ECS_PROCESS = """
title: Encoded PowerShell
id: aaaaaaaa-0000-0000-0000-000000000001
taxonomy: ecs
level: high
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    process.executable|endswith: '\\powershell.exe'
  condition: sel
"""

_ODD_FIELD = """
title: Odd field
id: aaaaaaaa-0000-0000-0000-000000000002
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    CustomVendorField: 'x'
  condition: sel
"""


def _magic(blob: bytes) -> int:
    return struct.unpack_from("<I", blob, 0)[0]


def test_sigma_taxonomy_renames_image_to_ecs():
    res = compile_rules(_PROCESS)
    assert res.errors == []
    assert res.dropped == []
    assert b"process.executable" in res.artifact
    assert b"Image" not in res.artifact
    assert _magic(res.artifact) == MAGIC
    assert res.sidecar[1]["mitre"] == "T1059.001"
    assert res.sidecar[1]["verdict"] == "alert"


def test_ecs_taxonomy_keeps_names_as_written():
    res = compile_rules(_ECS_PROCESS)
    assert res.errors == []
    assert b"process.executable" in res.artifact
    assert b"Image" not in res.artifact


def test_ecs_false_keeps_the_sigma_name():
    res = compile_rules(_PROCESS, ecs=False)
    assert res.errors == []
    assert b"Image" in res.artifact
    assert b"process.executable" not in res.artifact


def test_file_event_uses_catalog_leaves():
    res = compile_rules(
        """
title: File create
id: aaaaaaaa-0000-0000-0000-000000000030
logsource:
  category: file_event
  product: windows
detection:
  sel:
    TargetFilename|endswith: '\\\\x.dll'
    Image|endswith: '\\\\a.exe'
  condition: sel
"""
    )
    assert res.errors == []
    assert b"file.path" in res.artifact
    assert b"process.executable" in res.artifact
    assert b"TargetFilename" not in res.artifact


def test_windows_security_and_cloudtrail_and_auditd():
    security = compile_rules(
        """
title: Security
id: aaaaaaaa-0000-0000-0000-000000000031
logsource:
  product: windows
  service: security
detection:
  sel:
    EventID: 4624
    SubjectUserName: administrator
  condition: sel
"""
    )
    assert security.errors == []
    assert b"event.code" in security.artifact
    assert b"user.name" in security.artifact
    assert b"EventID" not in security.artifact

    trail = compile_rules(
        """
title: Trail
id: aaaaaaaa-0000-0000-0000-000000000032
logsource:
  product: aws
  service: cloudtrail
detection:
  sel:
    eventName: CreateUser
    eventSource: iam.amazonaws.com
  condition: sel
"""
    )
    assert trail.errors == []
    assert b"event.action" in trail.artifact
    assert b"event.provider" in trail.artifact

    auditd = compile_rules(
        """
title: Auditd exe
id: aaaaaaaa-0000-0000-0000-000000000033
logsource:
  product: linux
  service: auditd
detection:
  sel:
    exe|endswith: /nc
  condition: sel
"""
    )
    assert auditd.errors == []
    assert b"process.executable" in auditd.artifact
    rule = SigmaCollection.from_yaml(
        """
title: Auditd exe
id: aaaaaaaa-0000-0000-0000-000000000033
logsource:
  product: linux
  service: auditd
detection:
  sel:
    exe|endswith: /nc
  condition: sel
"""
    ).rules[0]
    apply_rule_taxonomy(rule, ecs_pipeline())
    assert rule.detection.detections["sel"].detection_items[0].field == "process.executable"


def test_spellings_without_a_catalog_leaf_stay_written():
    """TargetImage is the other process. ScriptBlockText has no ECS leaf."""
    access = compile_rules(
        """
title: Access
id: aaaaaaaa-0000-0000-0000-000000000034
logsource:
  category: process_access
  product: windows
detection:
  sel:
    SourceImage|endswith: '\\\\a.exe'
    TargetImage|endswith: '\\\\lsass.exe'
  condition: sel
"""
    )
    assert access.errors == []
    assert b"process.executable" in access.artifact
    assert b"TargetImage" in access.artifact

    script = compile_rules(
        """
title: Script
id: aaaaaaaa-0000-0000-0000-000000000035
logsource:
  category: ps_script
  product: windows
detection:
  sel:
    ScriptBlockText|contains: Invoke-Mimikatz
  condition: sel
"""
    )
    assert script.errors == []
    assert b"ScriptBlockText" in script.artifact


def test_unknown_field_is_compiled():
    """The backend does not know which fields a deployment produces."""
    res = compile_rules(_ODD_FIELD)
    assert res.errors == []
    assert res.dropped == []
    assert b"CustomVendorField" in res.artifact


def test_gate_can_drop_after_the_rename():
    def gate(rule, tax):
        fields = [
            it.field
            for det in rule.detection.detections.values()
            for it in det.detection_items
            if it.field
        ]
        if "process.executable" in fields and tax == "sigma":
            return "deployment does not produce process.executable"
        return None

    res = compile_rules(_PROCESS, gate=gate)
    assert res.sidecar == {}
    assert res.dropped[0]["reason"] == "deployment does not produce process.executable"


def test_backend_convert_returns_sigmac_bytes_and_corr_json():
    yaml = """
title: base
name: base_login
id: aaaaaaaa-0000-0000-0000-000000000010
logsource: {category: authentication, service: sshd}
detection:
  sel:
    User: root
  condition: sel
---
title: many failures
name: many_failures
status: stable
correlation:
  type: event_count
  rules:
    - base_login
  group-by:
    - User
  timespan: 10m
  condition:
    gte: 5
"""
    coll = SigmaCollection.from_yaml(yaml, resolve_references=False)
    backend = LibsigmaBackend()
    blob = backend.convert(coll, "sigmac")
    assert isinstance(blob, bytes)
    assert _magic(blob) == MAGIC
    text = backend.convert(coll, "corr")
    assert '"type": "event_count"' in text
    assert "user.name" in text
    assert backend.last_result.errors == []


def test_informational_is_benign_and_verdict_override_wins():
    res = compile_rules("""
title: context
level: informational
logsource: {category: firewall}
detection:
  sel:
    action: pass
  condition: sel
---
title: asked
level: informational
verdict: alert
logsource: {category: firewall}
detection:
  sel:
    action: block
  condition: sel
""")
    assert res.sidecar[1]["verdict"] == "benign"
    assert res.sidecar[2]["verdict"] == "alert"
    assert b"event.action" in res.artifact


def test_unresolved_placeholder_is_an_error():
    res = compile_rules("""
title: expand
logsource: {category: firewall}
detection:
  sel:
    src_ip|expand: '%edge%'
  condition: sel
""")
    assert res.sidecar == {}
    assert res.errors
    assert "edge" in res.errors[0]["error"]
