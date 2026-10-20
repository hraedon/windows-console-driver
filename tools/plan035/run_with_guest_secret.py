"""Plan 035 operator tool: run a host .ps1 with the guest secret as an argument.

The script receives (vm, user, secret, extra...). The secret is read from the
environment variable the estate names and travels over the host session, never
argv or output.

usage: run_with_guest_secret.py <estate.toml> <script.ps1> <user> [extra...]
"""

import os
import sys
from pathlib import Path

from wcd.cli import _default_transport
from wcd.estate import load_estate


def main() -> None:
    estate = load_estate(sys.argv[1])
    transport = _default_transport(estate)
    secret = os.environ[estate.password_env]
    args = [estate.vm_name, sys.argv[3], secret, *sys.argv[4:]]
    try:
        print(transport.host(Path(sys.argv[2]).read_text(), args, timeout=600))
    finally:
        transport.close()


if __name__ == "__main__":
    main()
