[CmdletBinding()]
param(
    [switch] $Offline,
    [string] $OutputDirectory
)

& (Join-Path $PSScriptRoot '../desktop/build-windows.ps1') -App Container @PSBoundParameters
