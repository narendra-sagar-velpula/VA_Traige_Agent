import json

import pytest

from vatriage.cli import main
from vatriage.evaluate import export_run, load_truth, score
from vatriage.models import Decision
from vatriage.reach import CodeIndex, advisory_symbols
from vatriage.report import markdown, openvex, remediation, sarif
from vatriage.rules import RuleEngine, apply_guardrails
from vatriage.sbom import read_cyclonedx
from vatriage.workspace import Workspace

from .conftest import ADV, KEV, LAB, SBOM, TRUTH


@pytest.fixture(scope="module")
def engines():
    idx = CodeIndex.build(LAB)
    _, comps = read_cyclonedx(SBOM)
    return {m: RuleEngine(idx, comps, m) for m in ("safe", "aggressive")}


def decide_all(engine, collected):
    return [engine.decide(f)[0] for f in collected["findings"]]


def test_advisory_symbols_ignore_prose_builtins_and_example_code():
    text = (
        "Pillow through 10.1.0 allows PIL.ImageMath.eval Arbitrary Code Execution. Raises ValueError. "
        "Uses `full_load` and the FullLoader. Example:\n```python\nhashes.SHA256()\n```"
    )
    syms = advisory_symbols(text, "pillow")
    assert {"PIL.ImageMath.eval", "full_load", "FullLoader"} <= syms
    assert "ValueError" not in syms and "hashes.SHA256" not in syms


def test_code_index_sees_imports_calls_keywords_and_template_filters():
    idx = CodeIndex.build(LAB)
    assert idx.imported("pyyaml")[0].file == "app/config_loader.py"
    assert idx.imported("pillow") and not idx.imported("paramiko")
    assert idx.find("FullLoader")[0].line == 8
    assert idx.find("urlize")[0].file == "templates/change_summary.html.j2"
    assert idx.find("Image.open")[0].file == "app/photos.py"
    assert not idx.imported("pytest")  # tests are excluded from reachability


def test_constant_expression_detection():
    idx = CodeIndex.build(LAB)
    query = idx.call_at("app/inventory.py", 15)
    assert idx.is_constant_expr("app/inventory.py", query.args[0])  # f-string with module constant TABLE
    injectable = idx.call_at("app/inventory.py", 10)
    assert not idx.is_constant_expr("app/inventory.py", injectable.args[0])


def test_safe_rules_never_dismiss_a_real_vulnerability(engines, collected, by_key):
    truth = load_truth(TRUTH)
    s = score(by_key, decide_all(engines["safe"], collected), truth)["overall"]
    assert s["findings"] == 85 and s["truly_affected"] == 17
    assert s["unsafe_dismissals"] == [] and s["affected_caught"] == 17
    assert s["automated"] == 30 and s["needs_review"] == 55
    assert len(s["false_alarms"]) == 7


def test_aggressive_rules_automate_more_but_dismiss_the_urlize_redos(engines, collected, by_key):
    s = score(by_key, decide_all(engines["aggressive"], collected), load_truth(TRUTH))["overall"]
    assert s["automated"] == 61
    assert s["unsafe_dismissals"] == ["sca:jinja2@2.10.1:PYSEC-2021-66"]


def test_kev_finding_is_never_dismissed_without_a_human(by_key):
    f = by_key["sca:pillow@10.0.0:PYSEC-2026-1794"]
    d = apply_guardrails(
        f,
        Decision(
            key=f.key,
            status="not_affected",
            priority="P4",
            justification="x",
            vex_justification="vulnerable_code_not_in_execute_path",
        ),
    )
    assert d.status == "needs_review" and d.needs_human and d.priority == "P1" and "CISA KEV" in d.guardrail


def test_specific_rule_decisions(engines, by_key):
    e = engines["safe"]
    assert e.decide(by_key["sca:paramiko@2.10.0:PYSEC-2026-1758"])[0].status == "not_affected"
    assert e.decide(by_key["sca:pynacl@1.6.0:PYSEC-2026-3002"])[0].status == "not_affected"
    assert e.decide(by_key["sca:pyyaml@5.3:PYSEC-2020-96"])[0].status == "affected"
    assert e.decide(by_key["sca:urllib3@1.23:PYSEC-2019-132"])[0].status == "needs_review"
    assert e.decide(by_key["sast:B608:app/inventory.py:15"])[0].status == "not_affected"
    assert e.decide(by_key["sast:B311:app/sessions.py:10"])[0].status == "affected"
    assert e.decide(by_key["sast:B311:app/sessions.py:15"])[0].status == "not_affected"
    assert e.decide(by_key["sast:B105:app/settings.py:9"])[0].status == "not_affected"
    assert e.decide(by_key["sast:B101:tests/test_inventory.py:10"])[0].status == "not_affected"


def test_reports(engines, collected, by_key):
    decisions = decide_all(engines["safe"], collected)
    meta = {k: v for k, v in collected.items() if k != "findings"}
    md = markdown(meta, by_key, decisions, "rules-safe")
    assert "## Remaining findings" in md and "## Not affected and false positives" in md
    assert "CVE-2023-4863" in md and "**KEV**" in md
    vex = openvex(meta, by_key, decisions, "tester")
    statuses = {s["status"] for s in vex["statements"]}
    assert statuses <= {"affected", "not_affected", "under_investigation"}
    assert all("justification" in s for s in vex["statements"] if s["status"] == "not_affected")
    sar = sarif(meta, by_key, decisions)
    assert sar["version"] == "2.1.0"
    assert all(r["level"] in ("error", "warning", "note") for r in sar["runs"][0]["results"])
    plan = {p["package"]: p for p in remediation(by_key, decisions)}
    assert plan["pyyaml"]["to"] == "5.4" and plan["pillow"]["to"] == "13.0.0"


def test_export_run_marks_affected_cases_critical(engines, collected, by_key):
    decisions = decide_all(engines["safe"], collected)
    run = export_run("x", "rules-safe", by_key, decisions, load_truth(TRUTH))
    assert len(run["results"]) == 85
    crit = [r for r in run["results"] if "critical" in r["tags"]]
    assert len(crit) == 17 and all(r["passed"] for r in crit)  # safe rules dismiss no real issue
    assert all("@" not in r["case_id"] for r in run["results"])


def test_workspace_blocks_path_traversal_and_redacts(findings_file):
    ws = Workspace.load(findings_file, LAB, SBOM, ADV, KEV)
    with pytest.raises(PermissionError):
        ws.read_code("../../../etc/passwd")
    text, lines = ws.read_code("app/settings.py", 1, 20)
    assert "Netcfg@2024!" not in text and lines[0] == 1
    assert ws.dependency_path("urllib3")["pulled_in_by"] == ["requests"]
    assert ws.advisory("CVE-2023-4863")["cisa_kev"] is not None


def test_cli_lab_and_gate(tmp_path, capsys):
    out = tmp_path / "out"
    assert main(["lab", "--out", str(out)]) == 0
    for name in (
        "findings.json",
        "decisions-safe.json",
        "va-report.md",
        "netcfg-service.openvex.json",
        "va-findings.sarif",
        "run-rules-safe.json",
        "run-rules-aggressive.json",
    ):
        assert (out / name).exists(), name
    assert main(["gate", str(out / "findings.json"), str(out / "decisions-safe.json")]) == 1
    assert (
        main(
            [
                "gate",
                str(out / "findings.json"),
                str(out / "decisions-safe.json"),
                "--baseline",
                str(out / "decisions-safe.json"),
            ]
        )
        == 0
    )
    assert (
        main(
            [
                "eval",
                str(out / "findings.json"),
                str(out / "decisions-aggressive.json"),
                "--truth",
                str(TRUTH),
                "--fail-on-unsafe",
            ]
        )
        == 1
    )
    run = json.loads((out / "run-rules-safe.json").read_text())
    assert run["run"]["agent"] == "va-triage-agent"
