"""Plan 035 operator tool: run one .ps1 on the Hyper-V host session. usage: hostq.py <estate.toml> <script.ps1> [args...]"""
import sys
from wcd.cli import _default_transport
from wcd.estate import load_estate
e = load_estate(sys.argv[1]); t = _default_transport(e)
try:
    print(t.host(open(sys.argv[2]).read(), sys.argv[3:], timeout=300))
finally:
    t.close()
