"""libsigma-sigmac: --fields drops rules on unlisted fields, --placeholders fills |expand."""

import json
import struct

import pytest

from sigma.backends.libsigma.cli import InputError, load_fields, load_placeholders, main
from sigma.backends.libsigma.format import MAGIC

SSH_RULE = """
title: ssh failure
id: 6f1c1d4e-0000-4000-8000-000000000001
status: test
logsource:
    product: linux
    service: sshd
detection:
    sel:
        event.outcome: failure
        source.ip: 192.0.2.10
    condition: sel
"""

PROC_RULE = """
title: shell spawn
id: 6f1c1d4e-0000-4000-8000-000000000002
status: test
logsource:
    product: linux
    category: process_creation
detection:
    sel:
        Image|endswith: /sh
    condition: sel
"""

LABEL_RULE = """
title: label leaf
id: 6f1c1d4e-0000-4000-8000-000000000003
status: test
taxonomy: ecs
logsource:
    product: linux
detection:
    sel:
        labels.queue: deferred
    condition: sel
"""

EXPAND_RULE = """
title: egress to listed nets
id: 6f1c1d4e-0000-4000-8000-000000000004
status: test
taxonomy: ecs
logsource:
    category: firewall
detection:
    sel:
        destination.ip|expand: '%egress_nets%'
    condition: sel
"""


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _rules_dir(tmp_path, *rules):
    d = tmp_path / "rules"
    d.mkdir()
    for i, text in enumerate(rules):
        (d / f"r{i}.yml").write_text(text, encoding="utf-8")
    return d


def _summary(capsys):
    err = capsys.readouterr().err
    line = next(l for l in err.splitlines() if l.startswith("rules "))
    parts = line.split()
    return {parts[i]: int(parts[i + 1]) for i in range(0, len(parts), 2)}, err


def test_load_fields_exact_and_prefix(tmp_path):
    path = _write(tmp_path, "fields.txt", "# produced\nsource.ip\n\nlabels.*  # leaves\n")
    accepted = load_fields(path)
    assert accepted("source.ip")
    assert accepted("labels.queue")
    assert not accepted("labels.")
    assert not accepted("destination.ip")


@pytest.mark.parametrize("body", ["", "# only a comment\n", "a b\n", "*\n", "source.*.ip\n", ".*\n"])
def test_load_fields_rejects_bad_files(tmp_path, body):
    with pytest.raises(InputError):
        load_fields(_write(tmp_path, "fields.txt", body))


def test_load_placeholders_accepts_scalar_and_list(tmp_path):
    path = _write(tmp_path, "ph.yml", "a: 192.0.2.0/24\nb: [x, y]\n")
    assert load_placeholders(path) == {"a": ["192.0.2.0/24"], "b": ["x", "y"]}
    path = _write(tmp_path, "ph.json", json.dumps({"a": ["198.51.100.0/24"]}))
    assert load_placeholders(path) == {"a": ["198.51.100.0/24"]}


@pytest.mark.parametrize("body", ["[]\n", "{}\n", "a: {b: c}\n", "a: []\n", "a: [x, {b: c}]\n"])
def test_load_placeholders_rejects_bad_files(tmp_path, body):
    with pytest.raises(InputError):
        load_placeholders(_write(tmp_path, "ph.yml", body))


def test_without_fields_every_rule_compiles(tmp_path, capsys):
    rules = _rules_dir(tmp_path, SSH_RULE, PROC_RULE)
    out = tmp_path / "out.sigmac"
    assert main([str(rules), "-o", str(out)]) == 0
    counts, _ = _summary(capsys)
    assert counts["rules"] == 2
    assert counts["dropped"] == 0
    assert struct.unpack_from("<I", out.read_bytes(), 0)[0] == MAGIC


def test_fields_drop_rules_on_unlisted_fields(tmp_path, capsys):
    rules = _rules_dir(tmp_path, SSH_RULE, PROC_RULE, LABEL_RULE)
    fields = _write(tmp_path, "fields.txt", "event.outcome\nsource.ip\nlabels.*\n")
    out = tmp_path / "out.sigmac"
    assert main([str(rules), "-o", str(out), "--fields", str(fields)]) == 0
    counts, _ = _summary(capsys)
    # process_creation renames Image to process.executable, which is not listed.
    assert counts["rules"] == 2
    assert counts["dropped"] == 1


def test_placeholders_fill_expand(tmp_path, capsys):
    rules = _rules_dir(tmp_path, EXPAND_RULE)
    out = tmp_path / "out.sigmac"
    assert main([str(rules), "-o", str(out)]) == 0
    counts, err = _summary(capsys)
    assert counts["rules"] == 0
    assert counts["errors"] == 1
    assert "unresolved |expand placeholder" in err

    ph = _write(tmp_path, "ph.yml", "egress_nets: [255.255.255.255/32]\n")
    assert main([str(rules), "-o", str(out), "--placeholders", str(ph)]) == 0
    counts, _ = _summary(capsys)
    assert counts["rules"] == 1
    assert counts["errors"] == 0


def test_bad_input_file_exits_2(tmp_path, capsys):
    rules = _rules_dir(tmp_path, SSH_RULE)
    out = tmp_path / "out.sigmac"
    bad = _write(tmp_path, "fields.txt", "a b\n")
    assert main([str(rules), "-o", str(out), "--fields", str(bad)]) == 2
    assert "one field per line" in capsys.readouterr().err
    assert not out.exists()
    missing = tmp_path / "absent.yml"
    assert main([str(rules), "-o", str(out), "--placeholders", str(missing)]) == 2
