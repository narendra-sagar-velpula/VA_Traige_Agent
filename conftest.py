from pathlib import Path

import pytest

from vatriage.pipeline import collect
from vatriage.workspace import save_findings

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "lab" / "netcfg-service"
SBOM = LAB / "sbom" / "netcfg-service.cdx.json"
ADV = ROOT / "data" / "advisories"
KEV = ROOT / "data" / "kev.json"
TRUTH = ROOT / "lab" / "ground_truth.yaml"


@pytest.fixture(scope="session")
def collected():
    return collect(SBOM, [str(LAB / "bandit.json")], None, ADV, KEV, LAB)


@pytest.fixture(scope="session")
def findings_file(tmp_path_factory, collected):
    path = tmp_path_factory.mktemp("ws") / "findings.json"
    save_findings(path, collected)
    return path


@pytest.fixture(scope="session")
def by_key(collected):
    return {f.key: f for f in collected["findings"]}
