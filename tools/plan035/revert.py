"""Plan 035 operator tool, MUTATING: restore the estate member to its checkpoint.

Restore-VMSnapshot with -Confirm:$false (the window-9 rule: without it the
cmdlet throws a bare NullReferenceException in a headless WinRM session).

usage: revert.py <estate.toml>
"""

import sys

from wcd.cli import _default_transport
from wcd.estate import load_estate

SCRIPT = r"""param($vm,$cp)
$ErrorActionPreference='Stop'
$s = Get-VMSnapshot -VMName $vm -Name $cp
"before_state=$((Get-VM -Name $vm).State)"
Restore-VMSnapshot -VMSnapshot $s -Confirm:$false
"restored=$cp"
"after_state=$((Get-VM -Name $vm).State)"
"""


def main() -> None:
    estate = load_estate(sys.argv[1])
    transport = _default_transport(estate)
    try:
        print(transport.host(SCRIPT, [estate.vm_name, estate.checkpoint_name], timeout=600))
    finally:
        transport.close()


if __name__ == "__main__":
    main()
