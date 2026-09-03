"""Regenerate the R3/R4 fixtures byte-exactly (UTF-16LE BOM + CRLF)."""

from pathlib import Path

ROOT = Path(__file__).parent

tmpl_lines = [
    "[Unicode]",
    "Unicode=yes",
    "[System Access]",
    "MinimumPasswordAge = 1",
    "MaximumPasswordAge = 42",
    "LockoutBadCount = 13",
    "[Registry Keys]",
    '"MACHINE\\SOFTWARE\\zzStudioAlpha",2,"D:PAR(A;OICI;FA;;;BA)"',
    '"MACHINE\\SOFTWARE\\zzStudioBravo",1,"D:PAR(A;OICI;FA;;;BA)"',
    '"MACHINE\\SOFTWARE\\zzStudioCharlie",0,"D:PAR(A;OICI;FA;;;BA)"',
    "[File Security]",
    '"C:\\zzStudioData",1,"D:PAR(A;OICI;FA;;;BA)"',
    "[Group Membership]",
    "*S-1-5-32-544__Members = *S-1-5-21-1111111111-2222222222-3333333333-512",
    "[Service General Setting]",
    "wuauserv,3,2",
]
text = "\r\n".join(tmpl_lines) + "\r\n"
data = b"\xff\xfe" + text.encode("utf-16-le")
(ROOT / "GptTmpl.inf").write_bytes(data)
print("gpttmpl:", len(data), "bytes")

fdeploy_lines = [
    "[Initialize]",
    "SidsAddedByGPMC=S-1-5-21-1111111111-2222222222-3333333333-513",
    "[{25537BA6-77A8-11D2-9B6C-0000F8080861}]",
    '"Documents"="\\\\zz-studio-fileserver\\zzredir\\%username%"',
]
text2 = "\r\n".join(fdeploy_lines) + "\r\n"
data2 = b"\xff\xfe" + text2.encode("utf-16-le")
(ROOT / "fdeploy.ini").write_bytes(data2)
print("fdeploy:", len(data2), "bytes")
