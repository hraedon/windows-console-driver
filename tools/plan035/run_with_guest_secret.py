"""Plan 035 operator tool: run a host .ps1 with args (vm, <user>, guest secret from the env
the estate names, extra args...). The secret travels over the host session, never argv.
usage: run_with_guest_secret.py <estate.toml> <script.ps1> <user> [extra...]"""
import os, sys
from wcd.cli import _default_transport
from wcd.estate import load_estate
e = load_estate(sys.argv[1]); t = _default_transport(e)
script = open(sys.argv[2]).read()
try:
    print(t.host(script, [e.vm_name, sys.argv[3], os.environ["GUEST_BOOTSTRAP_PASSWORD"]] + sys.argv[4:], timeout=600))
finally:
    t.close()
