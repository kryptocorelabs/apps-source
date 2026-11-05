[CmdletBinding()]
param(
    [switch] $Offline,
    [string] $TorBundleRoot,
    [string] $OutputDirectory
)

& (Join-Path $PSScriptRoot '../desktop/build-windows.ps1') -App Msg @PSBoundParameters
