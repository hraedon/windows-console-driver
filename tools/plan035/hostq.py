"""Plan 035 operator tool: run one .ps1 on the Hyper-V host session.

usage: hostq.py <estate.toml> <script.ps1> [args...]
"""

import sys
from pathlib import Path

from wcd.cli import _default_transport
from wcd.estate import load_estate


def main() -> None:
    transport = _default_transport(load_estate(sys.argv[1]))
    try:
        print(transport.host(Path(sys.argv[2]).read_text(), sys.argv[3:], timeout=300))
    finally:
        transport.close()


if __name__ == "__main__":
    main()
