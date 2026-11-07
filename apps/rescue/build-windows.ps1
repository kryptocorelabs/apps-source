[CmdletBinding()]
param(
    [switch] $Offline,
    [string] $OutputDirectory = 'dist/apps/rescue/prototype/windows-x64'
)

$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Push-Location $repository
try {
    $arguments = @('build', '--locked', '--release', '-p', 'kryptocore-rescue')
    if ($Offline) { $arguments += '--offline' }
    & cargo @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Building the read-only Rescue worker failed.' }
    $target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { 'target' }
    $engine = (Resolve-Path (Join-Path $target 'release/kryptocore-rescue.exe')).Path
    $output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
    $publish = @('publish', 'apps/rescue/windows/Rescue.csproj', '-c', 'Release', '-r', 'win-x64',
        '--self-contained', 'true', '-o', $output, '-p:PublishSingleFile=true',
        '-p:IncludeNativeLibrariesForSelfExtract=true', '-p:EnableCompressionInSingleFile=true',
        '-p:DebugType=embedded', "-p:RescueEnginePath=$engine")
    if ($Offline) {
        $packages = if ($env:NUGET_PACKAGES) { $env:NUGET_PACKAGES } else { Join-Path $env:USERPROFILE '.nuget/packages' }
        $publish += @('--source', (Resolve-Path $packages).Path)
    }
    & dotnet @publish
    if ($LASTEXITCODE -ne 0) { throw 'Building the Rescue prototype interface failed.' }
}
finally { Pop-Location }
