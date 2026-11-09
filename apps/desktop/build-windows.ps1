[CmdletBinding()]
param(
    [switch] $Offline,
    [ValidateSet('All', 'Container', 'Msg')][string] $App = 'All',
    [string] $TorBundleRoot = 'dist/msg-tor-setup',
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { 'target' }
$cargoArguments = @('build', '--locked', '--release', '-p', 'kryptocore-desktop-engine')
if ($Offline) {
    $cargoArguments += '--offline'
    $localPackages = if ($env:NUGET_PACKAGES) {
        $env:NUGET_PACKAGES
    } else {
        Join-Path $env:USERPROFILE '.nuget/packages'
    }
    $localPackages = (Resolve-Path -LiteralPath $localPackages).Path
}

Push-Location $repository
try {
    & cargo @cargoArguments
    if ($LASTEXITCODE -ne 0) { throw 'Building the Rust engine failed.' }
    $engine = (Resolve-Path (Join-Path $target 'release/kryptocore-desktop-engine.exe')).Path

    $apps = if ($App -eq 'All') { 'Container', 'Msg' } else { @($App) }
    foreach ($product in $apps) {
        $slug = $product.ToLowerInvariant()
        $project = Join-Path $repository "apps/$slug/windows/$product.csproj"
        $destination = if ($OutputDirectory) { $OutputDirectory } else { "dist/apps/$slug/windows-x64" }
        $output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($destination)
        $publish = @(
            'publish', $project, '-c', 'Release', '-r', 'win-x64', '--self-contained', 'true',
            '-o', $output, '-p:PublishSingleFile=true', '-p:IncludeNativeLibrariesForSelfExtract=true',
            '-p:EnableCompressionInSingleFile=true', '-p:DebugType=embedded', "-p:DesktopEnginePath=$engine"
        )
        if ($product -eq 'Msg') {
            $tor = (Resolve-Path -LiteralPath $TorBundleRoot).Path
            $expectedHash = [IO.File]::ReadAllText((Join-Path $repository 'apps/msg/windows/tor-bundle.sha256')).Trim()
            $hash = (Get-FileHash -LiteralPath (Join-Path $tor 'tor/tor.exe') -Algorithm SHA256).Hash
            if ($hash -cne $expectedHash) {
                throw 'Expected the verified Windows x64 Tor Expert Bundle 16.0 binary. Verify and update the pinned hash before changing versions.'
            }
            $publish += "-p:TorBundleRoot=$tor"
        }
        if ($Offline) { $publish += @('--source', $localPackages) }
        & dotnet @publish
        if ($LASTEXITCODE -ne 0) { throw "Building the $product Windows app failed." }
        $binaryName = if ($product -eq 'Msg') { 'MSG' } else { $product }
        & (Join-Path $repository 'apps/desktop/tests/check-portable.ps1') -Product $product `
            -Executable (Join-Path $output "KryptoCore-$binaryName.exe") `
            -OutputDirectory (Join-Path $output 'verification')
    }
}
finally {
    Pop-Location
}
