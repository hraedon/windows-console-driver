from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from wcd.cli import main
from wcd.iis_evidence import IisEvidenceError, config_history, read_config

LOCATION = "Synthetic Site/Enrollment"
CONFIG = (Path(__file__).parent / "fixtures/iis/applicationHost.config").read_bytes()


def test_banked_read_sources_and_synthetic_corpus_remain_bound() -> None:
    root = Path(__file__).resolve().parents[1]
    record = json.loads(
        (root / "docs/iis-evidence-20261014/records/iis-read-qualification.json").read_text()
    )
    assert record["capability_qualification"] is False
    for name, digest in record["source_sha256"].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
    corpus = record["synthetic_corpus"]
    assert hashlib.sha256((root / corpus["path"]).read_bytes()).hexdigest() == corpus["sha256"]


def test_committed_truth_has_typed_values_scope_and_lock_provenance() -> None:
    config = read_config(CONFIG, [LOCATION])
    row = config["locations"][LOCATION]
    assert row["apphost_global"]["token_checking"] is None
    truth = row["apphost_location"]
    assert truth["token_checking"] == "Require"
    assert truth["ssl_flags"] == ["Ssl", "Ssl128"]
    assert truth["enabled"] is True
    assert truth["provider_operations"][0] == {"operation": "clear"}
    assert truth["provider_operations"][1] == {"operation": "add", "value": "Negotiate"}
    assert all(s["app_scope_locked"] is True for s in row["lock_state"])
    assert all(s["source"] == "configSections" for s in row["lock_state"])


def test_missing_location_and_attributes_remain_unknown() -> None:
    row = read_config(b"<configuration/>", [LOCATION])["locations"][LOCATION]
    assert row["apphost_location"] is None
    assert row["apphost_global"]["enabled"] is None
    assert row["lock_state"][0]["app_scope_locked"] is None


@pytest.mark.parametrize(
    "payload",
    [
        CONFIG.replace(b"Require", b"No"),
        CONFIG.replace(b"Ssl128", b"Typo"),
        CONFIG.replace(b'enabled="true"', b'enabled="maybe"'),
        b"<invalid/>",
        b"<broken",
        b'<!DOCTYPE configuration [<!ENTITY a "b">]><configuration/>',
        CONFIG.replace(b"</configuration>", CONFIG[CONFIG.index(b"<location") :]),
    ],
)
def test_invalid_ambiguous_or_unknown_values_refused(payload: bytes) -> None:
    with pytest.raises(IisEvidenceError):
        read_config(payload, [LOCATION])


def test_history_finds_dirty_variants_and_compares_live_to_snapshot(tmp_path: Path) -> None:
    live = tmp_path / "applicationHost.config"
    live.write_bytes(CONFIG)
    history = tmp_path / "history"
    history.mkdir()
    for number in (27, 33, 34, 35, 36):
        directory = history / f"CFGHISTORY_{number:010}"
        directory.mkdir()
        (directory / live.name).write_bytes(
            CONFIG.replace(b"Require", b"None") if number in {34, 36} else CONFIG
        )
    result = config_history(live, history, [LOCATION], "CFGHISTORY_0000000035")
    assert result["diffs"]["live"]["bytes_equal"] is True
    for number in (34, 36):
        assert result["diffs"][f"CFGHISTORY_{number:010}"]["bytes_equal"] is False
        assert result["diffs"][f"CFGHISTORY_{number:010}"]["locations_equal"] is False
    with pytest.raises(IisEvidenceError, match="enumerated"):
        config_history(live, history, [LOCATION], "../../unrelated")


def test_read_commands_do_not_load_estate_or_contact_transport(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    live = tmp_path / "applicationHost.config"
    live.write_bytes(CONFIG)
    assert (
        main(
            [
                "--estate",
                "absent.toml",
                "read-iis-security-value",
                "--config",
                str(live),
                "--location",
                LOCATION,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["locations"][LOCATION]["apphost_location"]
    assert (
        main(
            [
                "read-iis-security-value",
                "--config",
                str(tmp_path / "absent"),
                "--location",
                LOCATION,
            ]
        )
        == 2
    )


def test_unread_history_is_explicit_and_nonzero(tmp_path: Path) -> None:
    live = tmp_path / "live.config"
    live.write_bytes(CONFIG)
    history = tmp_path / "history"
    (history / "CFGHISTORY_0000000001").mkdir(parents=True)
    result = config_history(live, history, [LOCATION], "live")
    assert result["diffs"]["CFGHISTORY_0000000001"] == {"error": "unreadable_config"}
    assert (
        main(
            [
                "iis-config-history",
                "--config",
                str(live),
                "--history",
                str(history),
                "--location",
                LOCATION,
            ]
        )
        == 3
    )
