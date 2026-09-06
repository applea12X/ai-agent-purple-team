from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from purpleloop.runtime.demo import ROOT, ComposeFixture, credentials


def test_compose_isolation_contract() -> None:
    config = yaml.safe_load((ROOT / "compose.phase1.yaml").read_text())
    fixture = config["services"]["phase1-fixture"]
    assert fixture["read_only"] and fixture["tmpfs"]
    assert fixture["cap_drop"] == ["ALL"] and fixture["security_opt"] == ["no-new-privileges:true"]
    assert fixture["networks"] == ["phase1-isolated"]
    assert config["networks"]["phase1-isolated"]["internal"]
    relay = config["services"]["phase1-ingress"]
    assert all(port.startswith("127.0.0.1:") for port in relay["ports"])
    assert "environment" not in relay


@pytest.mark.skipif(
    os.environ.get("PURPLELOOP_CONTAINER_TESTS") != "1", reason="explicit container acceptance lane"
)
async def test_container_denies_egress_and_cross_plane_credentials(tmp_path: Path) -> None:
    customer, control = credentials()
    fixture = ComposeFixture(customer, control)
    try:
        await fixture.start()
        checks = [
            "import os; assert os.getuid()!=0",
            "from pathlib import Path\n"
            "try: Path('/must-be-readonly').write_text('x')\n"
            "except OSError: pass\n"
            "else: raise AssertionError('writable root')",
            "import socket\n"
            "s=socket.socket();s.settimeout(0.2)\n"
            "try: s.connect(('1.1.1.1',443))\n"
            "except OSError: pass\n"
            "else: raise AssertionError('external egress')\n"
            "finally: s.close()",
            "import os,urllib.request,urllib.error\n"
            "r=urllib.request.Request('http://127.0.0.1:8081/control/snapshot',"
            "headers={'Authorization':'Bearer '+os.environ['PURPLELOOP_CUSTOMER_CREDENTIAL']})\n"
            "try: urllib.request.urlopen(r,timeout=1)\n"
            "except urllib.error.HTTPError as e: assert e.code==403\n"
            "else: raise AssertionError('control credential bypass')",
        ]
        for code in checks:
            await fixture.command(
                "exec", "-T", "phase1-fixture", "/app/.venv/bin/python", "-c", code
            )
        import httpx

        async with httpx.AsyncClient(trust_env=False) as client:
            response = await client.get(
                "http://127.0.0.1:18081/control/snapshot",
                headers={"Authorization": f"Bearer {control}"},
            )
            assert response.status_code == 200
    finally:
        await fixture.close()
    assert fixture.closed
