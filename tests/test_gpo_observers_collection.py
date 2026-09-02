"""Tests for the transport-typed observers and the FileTransport.

FileTransport serves the filesystem-backed snippets (scripts_ini_raw,
sysvol_tree_fingerprint) from the committed fixture tree; a ScriptedTransport
stands in for the AD-backed snippets. Envelope validation, value typing and
the fingerprint's two-pass agreement are exercised here without a guest.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest

from gpo_observers.collection import (
    AD_ATTRIBUTE_NAMES,
    SNIPPET_AD_ATTRIBUTES,
    SNIPPET_SCRIPTS_INI_RAW,
    SNIPPET_SYSVOL_TREE_FINGERPRINT,
    CollectionError,
    FileTransport,
    Transport,
    observe_ad_attributes,
    observe_identity,
    observe_scope,
    observe_scripts_ini,
    observe_sysvol_fingerprint,
    observe_version_values,
)
from gpo_observers.facts import JSONValue
from gpo_observers.psl import PSL_SNIPPETS

GPO_GUID = "11111111-2222-3333-4444-555555555555"
GPO_ROOT = Path(__file__).parent / "fixtures" / "gpo-tree" / GPO_GUID
SNIPPET_NAMES = {
    "gpo_identity",
    "sysvol_tree_fingerprint",
    "ad_attributes",
    "version_values",
    "scripts_ini_raw",
    "scope_forbid",
}


class ScriptedTransport:
    """Serves responses from a dict; optionally delegates file-backed snippets."""

    def __init__(
        self,
        responses: Mapping[str, dict[str, JSONValue]],
        file_transport: FileTransport | None = None,
    ) -> None:
        self._responses = dict(responses)
        self._file_transport = file_transport

    def __call__(
        self, snippet: str, params: Mapping[str, JSONValue]
    ) -> dict[str, JSONValue]:
        if self._file_transport is not None and snippet in (
            SNIPPET_SCRIPTS_INI_RAW,
            SNIPPET_SYSVOL_TREE_FINGERPRINT,
        ):
            return self._file_transport(snippet, params)
        try:
            return self._responses[snippet]
        except KeyError:
            raise CollectionError(f"no scripted response for snippet {snippet!r}") from None


def test_psl_snippet_names_match_collection_constants() -> None:
    from gpo_observers.collection import (
        SNIPPET_GPO_IDENTITY,
        SNIPPET_SCOPE_FORBID,
        SNIPPET_VERSION_VALUES,
    )

    assert set(PSL_SNIPPETS) == SNIPPET_NAMES
    assert {
        SNIPPET_GPO_IDENTITY,
        SNIPPET_SYSVOL_TREE_FINGERPRINT,
        SNIPPET_AD_ATTRIBUTES,
        SNIPPET_VERSION_VALUES,
        SNIPPET_SCRIPTS_INI_RAW,
        SNIPPET_SCOPE_FORBID,
    } == SNIPPET_NAMES


class TestEnvelopeValidation:
    def test_ok_envelope_yields_data(self) -> None:
        transport = ScriptedTransport(
            {"gpo_identity": {"ok": True, "data": {"gpo_guid": GPO_GUID, "domain_dns": "d"}}}
        )
        identity = observe_identity(transport, gpo_guid=GPO_GUID, domain_dns="d")
        assert identity.gpo_guid == GPO_GUID
        assert identity.domain_dns == "d"

    def test_error_envelope_raises(self) -> None:
        transport = ScriptedTransport({"gpo_identity": {"ok": False, "error": "boom"}})
        with pytest.raises(CollectionError, match="boom"):
            observe_identity(transport, gpo_guid=GPO_GUID, domain_dns="d")

    def test_missing_ok_raises(self) -> None:
        transport = ScriptedTransport({"gpo_identity": {"data": {}}})
        with pytest.raises(CollectionError, match="'ok'"):
            observe_identity(transport, gpo_guid=GPO_GUID, domain_dns="d")

    def test_non_bool_ok_raises(self) -> None:
        transport = ScriptedTransport({"gpo_identity": {"ok": "yes", "data": {}}})
        with pytest.raises(CollectionError, match="boolean"):
            observe_identity(transport, gpo_guid=GPO_GUID, domain_dns="d")

    def test_missing_data_raises(self) -> None:
        transport = ScriptedTransport({"gpo_identity": {"ok": True}})
        with pytest.raises(CollectionError, match="'data'"):
            observe_identity(transport, gpo_guid=GPO_GUID, domain_dns="d")

    def test_unscripted_snippet_raises(self) -> None:
        transport = ScriptedTransport({})
        with pytest.raises(CollectionError, match="no scripted response"):
            transport("ad_attributes", {})


class TestObserveIdentity:
    def test_rejects_malformed_guid(self) -> None:
        transport = ScriptedTransport(
            {"gpo_identity": {"ok": True, "data": {"gpo_guid": "not-a-guid", "domain_dns": "d"}}}
        )
        with pytest.raises(CollectionError, match="not a GUID"):
            observe_identity(transport, gpo_guid=GPO_GUID, domain_dns="d")

    def test_accepts_braced_guid_any_case(self) -> None:
        transport = ScriptedTransport(
            {
                "gpo_identity": {
                    "ok": True,
                    "data": {"gpo_guid": "{" + GPO_GUID.upper() + "}", "domain_dns": "d"},
                }
            }
        )
        identity = observe_identity(transport, gpo_guid=GPO_GUID, domain_dns="d")
        assert identity.gpo_guid == "{" + GPO_GUID.upper() + "}"


class TestObserveAdAttributes:
    def _data(self, **overrides: JSONValue) -> dict[str, JSONValue]:
        values: dict[str, JSONValue] = {
            "gPCMachineExtensionNames": "[{A}{B}]",
            "gPCUserExtensionNames": None,
            "versionNumber": 65537,
            "gPCFunctionalityVersion": 2,
            "flags": 0,
            "whenChanged": "2026-09-01T10:00:00.0000000Z",
            "uSNChanged": "1000",
        }
        values.update(overrides)
        return values

    def test_all_attributes_are_typed(self) -> None:
        transport = ScriptedTransport(
            {SNIPPET_AD_ATTRIBUTES: {"ok": True, "data": self._data()}}
        )
        values = observe_ad_attributes(transport, gpo_guid=GPO_GUID)
        assert set(values) == set(AD_ATTRIBUTE_NAMES)
        assert values["versionNumber"] == 65537
        assert values["flags"] == 0
        assert values["gPCUserExtensionNames"] is None
        assert values["uSNChanged"] == "1000"

    def test_missing_attribute_raises(self) -> None:
        data = self._data()
        del data["flags"]
        transport = ScriptedTransport({SNIPPET_AD_ATTRIBUTES: {"ok": True, "data": data}})
        with pytest.raises(CollectionError, match="missing attribute 'flags'"):
            observe_ad_attributes(transport, gpo_guid=GPO_GUID)

    def test_wrong_type_raises(self) -> None:
        transport = ScriptedTransport(
            {SNIPPET_AD_ATTRIBUTES: {"ok": True, "data": self._data(versionNumber="65537")}}
        )
        with pytest.raises(CollectionError, match="versionNumber"):
            observe_ad_attributes(transport, gpo_guid=GPO_GUID)

    def test_bool_is_not_an_int(self) -> None:
        transport = ScriptedTransport(
            {SNIPPET_AD_ATTRIBUTES: {"ok": True, "data": self._data(flags=True)}}
        )
        with pytest.raises(CollectionError, match="flags"):
            observe_ad_attributes(transport, gpo_guid=GPO_GUID)


class TestObserveVersionValues:
    def _response(self, **overrides: JSONValue) -> dict[str, JSONValue]:
        gpt_b64 = base64.b64encode((GPO_ROOT / "GPT.INI").read_bytes()).decode("ascii")
        data: dict[str, JSONValue] = {
            "gpt_ini_b64": gpt_b64,
            "gpt_version_raw": "65537",
            "ad_version_number": 65538,
        }
        data.update(overrides)
        return {"ok": True, "data": data}

    def test_unpacks_machine_and_user(self) -> None:
        transport = ScriptedTransport({"version_values": self._response()})
        values = observe_version_values(
            transport, gpt_ini_path="\\\\host\\GPT.INI", gpo_guid=GPO_GUID
        )
        assert values.version == 65537
        assert values.machine == 1
        assert values.user == 1
        assert values.display_name == "New Group Policy Object"
        assert values.ad_version_number == 65538

    def test_guest_side_version_must_match_payload(self) -> None:
        transport = ScriptedTransport({"version_values": self._response(gpt_version_raw="999")})
        with pytest.raises(CollectionError, match="does not match"):
            observe_version_values(transport, gpt_ini_path="x", gpo_guid=GPO_GUID)

    def test_invalid_base64_raises(self) -> None:
        transport = ScriptedTransport(
            {"version_values": self._response(gpt_ini_b64="!!!not base64!!!")}
        )
        with pytest.raises(CollectionError, match="base64"):
            observe_version_values(transport, gpt_ini_path="x", gpo_guid=GPO_GUID)

    def test_missing_gpt_ini_yields_null_versions(self) -> None:
        transport = ScriptedTransport(
            {
                "version_values": self._response(
                    gpt_ini_b64=None, gpt_version_raw=None, ad_version_number=None
                )
            }
        )
        values = observe_version_values(transport, gpt_ini_path="x", gpo_guid=GPO_GUID)
        assert values.version is None
        assert values.machine is None
        assert values.user is None


class TestObserveScriptsIni:
    def test_parses_both_fixture_files(self) -> None:
        transport = FileTransport(GPO_ROOT)
        facts = observe_scripts_ini(
            transport, scripts_dir="\\\\host\\SYSVOL\\Machine\\Scripts", side="machine"
        )
        assert facts["scripts_ini.machine.present"] is True
        assert facts["scripts_ini.ps.machine.present"] is True
        assert facts["scripts_ini.machine.Startup.0.script"] == "agent-startup.cmd"
        assert facts["scripts_ini.ps.machine.Startup.0.script"] == "bootstrap-evidence.ps1"
        assert facts["scripts_ini.ps.machine.config_shape"] == "scripts_config"

    def test_side_detection_user_directory(self) -> None:
        transport = FileTransport(GPO_ROOT)
        facts = observe_scripts_ini(
            transport, scripts_dir="\\\\host\\SYSVOL\\User\\Scripts", side="user"
        )
        assert facts["scripts_ini.user.present"] is False
        assert facts["scripts_ini.ps.user.present"] is False
        assert facts["scripts_ini.user.encoding.bom"] is None

    def test_invalid_side_raises(self) -> None:
        transport = FileTransport(GPO_ROOT)
        with pytest.raises(ValueError, match="side"):
            observe_scripts_ini(transport, scripts_dir="x", side="both")


class TestObserveScope:
    def test_normalizes_to_sorted_tuples(self) -> None:
        transport = ScriptedTransport(
            {
                "scope_forbid": {
                    "ok": True,
                    "data": {
                        "extension_list_machine": "[{A}{B}]",
                        "extension_list_user": None,
                        "policies_gpc_guids": ["{B}", "{A}"],
                        "sysvol_relpaths": ["{G}/Machine", "{G}/", "{G}/User"],
                    },
                }
            }
        )
        scope = observe_scope(
            transport, gpo_guid=GPO_GUID, domain_dns="d", sysvol_gpo_path="\\\\host\\{G}"
        )
        assert scope.policies_gpc_guids == ("{A}", "{B}")
        assert scope.sysvol_relpaths == ("{G}/", "{G}/Machine", "{G}/User")
        assert scope.extension_list_user is None

    def test_non_string_list_entries_raise(self) -> None:
        transport = ScriptedTransport(
            {
                "scope_forbid": {
                    "ok": True,
                    "data": {
                        "extension_list_machine": None,
                        "extension_list_user": None,
                        "policies_gpc_guids": [1],
                        "sysvol_relpaths": [],
                    },
                }
            }
        )
        with pytest.raises(CollectionError, match="policies_gpc_guids"):
            observe_scope(
                transport, gpo_guid=GPO_GUID, domain_dns="d", sysvol_gpo_path="x"
            )


class TestFileTransportFingerprint:
    def test_two_passes_match_and_cover_the_whole_tree(self) -> None:
        transport = FileTransport(GPO_ROOT)
        fingerprint = observe_sysvol_fingerprint(transport, sysvol_path="\\\\host\\{guid}")
        assert fingerprint.passes_match is True
        relpaths = {file.relpath for file in fingerprint.files}
        assert relpaths == {
            "Backup.xml",
            "GPT.INI",
            "Machine/Scripts/psscripts.ini",
            "Machine/Scripts/scripts.ini",
            "Machine/microsoft/.gpo-fingerprint-marker",
        }
        # Posix-normalized, no backslashes, no leading slashes.
        for file in fingerprint.files:
            assert "\\" not in file.relpath
            assert not file.relpath.startswith("/")
            assert len(file.sha256) == 64
            assert file.sha256 == file.sha256.lower()
            assert file.bytes > 0

    def test_hashes_match_independent_computation(self) -> None:
        transport = FileTransport(GPO_ROOT)
        fingerprint = observe_sysvol_fingerprint(transport, sysvol_path="x")
        scripts = next(
            file
            for file in fingerprint.files
            if file.relpath == "Machine/Scripts/scripts.ini"
        )
        expected = hashlib.sha256(
            (GPO_ROOT / "Machine" / "Scripts" / "scripts.ini").read_bytes()
        ).hexdigest()
        assert scripts.sha256 == expected
        assert scripts.bytes == (GPO_ROOT / "Machine" / "Scripts" / "scripts.ini").stat().st_size

    def test_hidden_marker_is_enumerated(self) -> None:
        # GPMC-style hidden files must not be skipped by either pass. The
        # marker carries the hidden attribute on Windows; the test does not
        # require it.
        transport = FileTransport(GPO_ROOT)
        fingerprint = observe_sysvol_fingerprint(transport, sysvol_path="x")
        assert any(".gpo-fingerprint-marker" in file.relpath for file in fingerprint.files)

    def test_fingerprint_detects_pass_disagreement(self) -> None:
        # A transport whose passes disagree must surface passes_match=False,
        # not silently pick one. Script a raw envelope to prove the
        # normalizer transports the verdict unchanged.
        class DisagreeingTransport:
            def __call__(
                self, snippet: str, params: Mapping[str, JSONValue]
            ) -> dict[str, JSONValue]:
                assert snippet == SNIPPET_SYSVOL_TREE_FINGERPRINT
                return {
                    "ok": True,
                    "data": {
                        "files": [{"relpath": "a.txt", "sha256": "a" * 64, "bytes": 1}],
                        "passes_match": False,
                    },
                }

        fingerprint = observe_sysvol_fingerprint(DisagreeingTransport(), sysvol_path="x")
        assert fingerprint.passes_match is False
        assert fingerprint.files[0].relpath == "a.txt"

    def test_invalid_sha256_raises(self) -> None:
        class BadHashTransport:
            def __call__(
                self, snippet: str, params: Mapping[str, JSONValue]
            ) -> dict[str, JSONValue]:
                return {
                    "ok": True,
                    "data": {
                        "files": [{"relpath": "a.txt", "sha256": "ZZ", "bytes": 1}],
                        "passes_match": True,
                    },
                }

        with pytest.raises(CollectionError, match="sha256"):
            observe_sysvol_fingerprint(BadHashTransport(), sysvol_path="x")

    def test_backslash_relpath_raises(self) -> None:
        class BackslashTransport:
            def __call__(
                self, snippet: str, params: Mapping[str, JSONValue]
            ) -> dict[str, JSONValue]:
                return {
                    "ok": True,
                    "data": {
                        "files": [{"relpath": "Machine\\a.txt", "sha256": "a" * 64, "bytes": 1}],
                        "passes_match": True,
                    },
                }

        with pytest.raises(CollectionError, match="posix"):
            observe_sysvol_fingerprint(BackslashTransport(), sysvol_path="x")


class TestFileTransportScriptsIniRaw:
    def test_serves_fixture_bytes_as_base64(self) -> None:
        transport = FileTransport(GPO_ROOT)
        envelope = transport(
            SNIPPET_SCRIPTS_INI_RAW, {"scripts_dir": "\\\\host\\Machine\\Scripts"}
        )
        assert envelope["ok"] is True
        data = envelope["data"]
        assert isinstance(data, dict)
        scripts = base64.b64decode(data["scripts_ini_b64"])
        assert scripts == (GPO_ROOT / "Machine" / "Scripts" / "scripts.ini").read_bytes()
        psscripts = base64.b64decode(data["psscripts_ini_b64"])
        assert psscripts == (GPO_ROOT / "Machine" / "Scripts" / "psscripts.ini").read_bytes()

    def test_side_detection_ignores_user_in_other_path_segments(self) -> None:
        # A host path such as C:\Users\...\Machine\Scripts must stay machine:
        # only the tail segment decides.
        transport = FileTransport(GPO_ROOT)
        envelope = transport(
            SNIPPET_SCRIPTS_INI_RAW,
            {"scripts_dir": "C:\\Users\\someone\\SYSVOL\\Machine\\Scripts"},
        )
        data = envelope["data"]
        assert isinstance(data, dict)
        assert data["scripts_ini_b64"] is not None
        assert data["psscripts_ini_b64"] is not None

    def test_absent_files_are_null(self) -> None:
        transport = FileTransport(GPO_ROOT)
        envelope = transport(
            SNIPPET_SCRIPTS_INI_RAW, {"scripts_dir": "\\\\host\\User\\Scripts"}
        )
        data = envelope["data"]
        assert isinstance(data, dict)
        assert data["scripts_ini_b64"] is None
        assert data["psscripts_ini_b64"] is None

    def test_unknown_snippet_without_fallback_raises(self) -> None:
        transport = FileTransport(GPO_ROOT)
        with pytest.raises(CollectionError, match="cannot serve"):
            transport("ad_attributes", {})

    def test_unknown_snippet_delegates_to_fallback(self) -> None:
        fallback = ScriptedTransport(
            {"ad_attributes": {"ok": True, "data": {"stub": True}}}
        )
        transport = FileTransport(GPO_ROOT, fallback=fallback)
        envelope = transport("ad_attributes", {})
        assert envelope == {"ok": True, "data": {"stub": True}}
        # File-backed snippets still win over the fallback.
        envelope = transport(SNIPPET_SCRIPTS_INI_RAW, {"scripts_dir": "Machine"})
        assert isinstance(envelope["data"], dict)
        assert "scripts_ini_b64" in envelope["data"]


def test_file_transport_satisfies_transport_protocol() -> None:
    def run(transport: Transport) -> dict[str, JSONValue]:
        return transport(SNIPPET_SCRIPTS_INI_RAW, {"scripts_dir": "Machine"})

    envelope = run(FileTransport(GPO_ROOT))
    assert envelope["ok"] is True
