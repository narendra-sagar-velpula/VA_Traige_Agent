import json

import pytest

from vatriage import cvss
from vatriage.advisories import BM25, KEV, Advisory, AdvisoryDB
from vatriage.pipeline import bandit_findings, clean, dedupe, redact, sarif_findings
from vatriage.sbom import dependents, from_pip_reports, read_cyclonedx, to_cyclonedx

from .conftest import ADV, LAB
from .conftest import KEV as KEV_PATH


@pytest.mark.parametrize(
    "vector,score",
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9),
        ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
        ("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_base_scores_match_the_specification(vector, score):
    assert cvss.base_score(vector) == score


def test_cvss_rejects_v2_and_broken_vectors():
    with pytest.raises(ValueError):
        cvss.base_score("AV:N/AC:L/Au:N/C:P/I:P/A:P")
    with pytest.raises(ValueError):
        cvss.base_score("CVSS:3.1/AV:N/AC:L")


def test_osv_version_ranges():
    a = Advisory(
        "X-1",
        "pkg",
        "",
        "",
        [],
        [[{"introduced": "1.2"}, {"fixed": "1.4.1"}], [{"introduced": "2.0"}, {"last_affected": "2.1"}]],
        {"0.9"},
    )
    assert [a.affects(v) for v in ("0.9", "1.1", "1.2", "1.4.0", "1.4.1", "2.0.5", "2.1", "2.2")] == [
        True,
        False,
        True,
        True,
        False,
        True,
        True,
        False,
    ]
    assert not a.affects("not-a-version")


def test_real_advisories_match_the_lab_pins():
    db = AdvisoryDB(ADV)
    ids = {a.id for a in db.matching("PyYAML", "5.3")}
    assert ids == {"PYSEC-2020-96", "PYSEC-2021-142"}
    assert {a.id for a in db.matching("pyyaml", "5.4")} == set()
    assert len(db.matching("Pillow", "10.0.0")) == 32


def test_kev_catalog_is_real_and_flags_libwebp():
    kev = KEV(KEV_PATH)
    assert kev.version and len(kev.entries) > 1000
    assert kev.lookup(["PYSEC-2026-1794", "CVE-2023-4863"]) is not None
    assert kev.lookup(["CVE-2020-1747"]) is None


def test_sbom_round_trip_and_dependency_paths(tmp_path):
    reports = [LAB / "sbom" / "pip-report-wheels.json", LAB / "sbom" / "pip-report-pyyaml.json"]
    comps = from_pip_reports(reports)
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(to_cyclonedx(comps, "svc", "1.0")))
    app, back = read_cyclonedx(path)
    assert app == "svc@1.0" and len(back) == 16
    assert {c.name for c in back if c.direct} == {"Jinja2", "requests", "Pillow", "cryptography", "paramiko", "PyYAML"}
    parents = dependents(back)
    assert parents["urllib3"] == ["requests"]
    assert parents["pynacl"] == ["paramiko"]
    assert parents["cffi"] == ["cryptography", "paramiko"]


def test_cleaning_strips_ansi_control_chars_and_caps_length():
    assert clean("\x1b[31mred\x1b[0m\x07 ok") == "red ok"
    assert clean("a" * 5000).endswith("…[truncated]")


def test_redaction_hides_secrets_but_keeps_field_names():
    out = redact('ADMIN_PASSWORD = "Netcfg@2024!"\nPASSWORD_FIELD = "password"\nkey AKIAABCDEFGHIJKLMNOP')
    assert "Netcfg@2024!" not in out and "[REDACTED 12 chars]" in out
    assert 'PASSWORD_FIELD = "password"' in out
    assert "AKIAABCDEFGHIJKLMNOP" not in out


def test_collect_dedupes_the_republished_libwebp_advisory(collected, by_key):
    assert collected["raw_findings"] == 86 and collected["merged"] == 1 and len(collected["findings"]) == 85
    libwebp = by_key["sca:pillow@10.0.0:PYSEC-2026-1794"]
    assert libwebp.kev and libwebp.also_reported_by == ["sca:pillow@10.0.0:PYSEC-2023-175"]
    assert "sca:pillow@10.0.0:PYSEC-2023-175" not in by_key
    assert sum(f.kev for f in collected["findings"]) == 1


def test_bandit_findings_are_redacted_before_anyone_reads_them(by_key):
    f = by_key["sast:B105:app/settings.py:6"]
    assert f.severity == "low" and f.cwe == ["CWE-259"]
    assert "Netcfg@2024!" not in (f.snippet or "") + f.details


def test_sarif_and_tool_dedupe(tmp_path, collected):
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semgrep",
                        "rules": [
                            {
                                "id": "python.lang.security.audit.subprocess-shell-true",
                                "properties": {"tags": ["CWE-78"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "python.lang.security.audit.subprocess-shell-true",
                        "level": "error",
                        "message": {"text": "shell=True"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app/diagnostics.py"},
                                    "region": {"startLine": 11},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    p = tmp_path / "semgrep.sarif"
    p.write_text(json.dumps(sarif))
    fs = sarif_findings(p, LAB)
    assert fs[0].key == "sast:python.lang.security.audit.subprocess-shell-true:app/diagnostics.py:11"
    assert fs[0].severity == "high" and fs[0].cwe == ["CWE-78"]
    bandit = [f for f in bandit_findings(LAB / "bandit.json", LAB) if f.key == "sast:B602:app/diagnostics.py:11"]
    merged, n = dedupe(bandit + fs)
    assert n == 1 and merged[0].also_reported_by == [fs[0].key]


def test_bm25_finds_the_relevant_advisory():
    idx = BM25(
        [
            ("a", "jinja2 urlize filter regular expression denial of service"),
            ("b", "pillow libwebp heap overflow"),
            ("c", "requests proxy authorization leak"),
        ]
    )
    assert idx.search("urlize ReDoS")[0][0] == "a"


def test_cli_search_uses_the_real_database(capsys):
    from vatriage.cli import main

    assert main(["search", "FullLoader arbitrary code execution", "--package", "pyyaml", "--advisories", str(ADV)]) == 0
    out = capsys.readouterr().out
    assert "PYSEC-2020-96" in out or "PYSEC-2021-142" in out
