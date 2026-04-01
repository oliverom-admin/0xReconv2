"""Architecture convention enforcement tests."""
from __future__ import annotations
from pathlib import Path

PACKAGES_ROOT = Path(__file__).parent.parent.parent  # packages/

# Only scan source packages, not tests — avoids false positives from test assertions.
_SOURCE_PACKAGES = (
    "recon-api/recon_api",
    "recon-core/recon_core",
    "recon-collectors/recon_collectors",
    "recon-agent/recon_agent",
)


def _py_files(package: str) -> list[Path]:
    root = PACKAGES_ROOT / package
    if not root.exists():
        return []
    return list(root.rglob("*.py"))


class TestConventions:

    def test_no_caip_in_source(self):
        allowed = ["caip-encrypted-blobs", "caip-encryption-metadata", "caip-signing-result"]
        violations = []
        for f in _py_files("recon-api/recon_api"):
            for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                if "caip" in line.lower() and not any(a in line.lower() for a in allowed):
                    violations.append(f"{f}:{i}: {line.strip()}")
        assert not violations, "\n".join(violations)

    def test_no_flask(self):
        violations = []
        for pkg in _SOURCE_PACKAGES:
            for f in _py_files(pkg):
                content = f.read_text(encoding="utf-8")
                if "from flask" in content or "import flask" in content:
                    violations.append(str(f))
        assert not violations, f"Flask found in: {violations}"

    def test_no_pykcs11(self):
        violations = []
        for pkg in _SOURCE_PACKAGES:
            for f in _py_files(pkg):
                if "PyKCS11" in f.read_text(encoding="utf-8"):
                    violations.append(str(f))
        assert not violations, f"PyKCS11 found in: {violations}"

    def test_no_requests_library(self):
        violations = []
        for pkg in _SOURCE_PACKAGES:
            for f in _py_files(pkg):
                content = f.read_text(encoding="utf-8")
                if "import requests" in content or "from requests" in content:
                    violations.append(str(f))
        assert not violations, f"requests found in: {violations}"

    def test_no_bare_except(self):
        violations = []
        for pkg in _SOURCE_PACKAGES:
            for f in _py_files(pkg):
                for i, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
                    s = line.strip()
                    if s in ("except:", "except Exception: pass", "except BaseException:"):
                        violations.append(f"{f}:{i}: {s}")
        assert not violations, "\n".join(violations)
