"""Estate file loader tests: the all-or-none host-credential trio."""

from __future__ import annotations

from pathlib import Path

import pytest

from wcd.estate import EstateError, load_estate

_BASE = (
    "[estate]\n"
    "host = 'zz-hyperv'\n"
    "vm_name = 'zz-vm'\n"
    "domain = 'zzlab.invalid'\n"
    "username = 'zz-operator'\n"
    "password_env = 'WCD_LAB_PASSWORD'\n"
)

_TRIO = (
    "host_user_domain = 'zz-corp.invalid'\n"
    "host_username = 'zz-controller'\n"
    "host_password_env = 'WCD_HOST_PASSWORD'\n"
)


def _estate_file(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "estate.toml"
    path.write_text(body, encoding="utf-8")
    return path


def test_the_host_trio_loads_and_reports_configured(tmp_path: Path) -> None:
    estate = load_estate(_estate_file(tmp_path, _BASE + _TRIO))
    assert estate.host_credentials_configured() is True
    assert estate.host_user_domain == "zz-corp.invalid"
    assert estate.host_username == "zz-controller"
    assert estate.host_password_env == "WCD_HOST_PASSWORD"


def test_absent_trio_stays_implicit(tmp_path: Path) -> None:
    estate = load_estate(_estate_file(tmp_path, _BASE))
    assert estate.host_credentials_configured() is False
    assert (estate.host_user_domain, estate.host_username, estate.host_password_env) == (
        "",
        "",
        "",
    )


@pytest.mark.parametrize(
    "partial",
    [
        "host_user_domain = 'zz-corp.invalid'\n",
        "host_username = 'zz-controller'\n",
        "host_password_env = 'WCD_HOST_PASSWORD'\n",
        "host_user_domain = 'zz-corp.invalid'\nhost_username = 'zz-controller'\n",
        "host_username = 'zz-controller'\nhost_password_env = 'WCD_HOST_PASSWORD'\n",
    ],
)
def test_a_partial_trio_is_refused_with_the_missing_keys(
    tmp_path: Path, partial: str
) -> None:
    with pytest.raises(EstateError, match="all-or-none"):
        load_estate(_estate_file(tmp_path, _BASE + partial))


def test_a_misspelled_host_key_is_still_an_unknown_key(tmp_path: Path) -> None:
    with pytest.raises(EstateError, match="unknown keys"):
        load_estate(_estate_file(tmp_path, _BASE + "host_user_domian = 'zz'\n"))
