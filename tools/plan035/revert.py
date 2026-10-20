"""Plan 035 operator tool: Restore-VMSnapshot the estate member to its checkpoint
(-Confirm:, window-9 rule). MUTATING. usage: revert.py <estate.toml>"""
import sys
from wcd.cli import _default_transport
from wcd.estate import load_estate
e = load_estate(sys.argv[1]); t = _default_transport(e)
try:
    script = r"""param($vm,$cp)
$ErrorActionPreference='Stop'
$s = Get-VMSnapshot -VMName $vm -Name $cp
"before_state=$((Get-VM -Name $vm).State)"
Restore-VMSnapshot -VMSnapshot $s -Confirm:$false
"restored=$cp"
"after_state=$((Get-VM -Name $vm).State)"
"""
    print(t.host(script, [e.vm_name, e.checkpoint_name], timeout=600))
finally:
    t.close()
