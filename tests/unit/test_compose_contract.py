from pathlib import Path

import yaml


def test_phase0_compose_fixture_is_isolated() -> None:
    compose = yaml.safe_load(
        (Path(__file__).parents[2] / "compose.yaml").read_text(encoding="utf-8")
    )
    service = compose["services"]["phase0-fixture"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    network = service["networks"][0]
    assert compose["networks"][network]["internal"] is True
