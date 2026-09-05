# PSScriptAnalyzer configuration for the PowerShell surfaces in this repository.
# CI fails on every Error or Warning that survives these narrowly documented
# exclusions.

@{
    Severity = @('Error', 'Warning')

    ExcludeRules = @(
        # False positive for the Invoke-Command block in hyperv-input.ps1. Its
        # variables are explicit param() entries populated through -ArgumentList;
        # $using: would be incorrect for that remoting contract.
        'PSUseUsingScopeModifierInNewRunspaces',

        # Credentials arrive from the broker in the process environment and are
        # converted to a PSCredential in-process. No secret enters argv, a file,
        # or output; prompting or a serialized credential would weaken the
        # intended broker boundary.
        'PSAvoidUsingConvertToSecureStringWithPlainText'
    )
}
