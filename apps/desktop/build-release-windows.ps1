[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $OutputDirectory,
    [string] $TorArchive
)

$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$toolchain = '1.99.1-x86_64-pc-windows-msvc'
$dotnetSdk = '10.0.403'
$dotnetRuntime = '10.0.14'
$torSha256 = '2ee123e9167318a3742778ff704e75f01d4780f05a14522d451fe011011077c4'

Push-Location $repository
try {
    $source = git rev-parse --verify HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Cannot identify the source commit.' }
    $changes = git status --porcelain --untracked-files=all
    if ($LASTEXITCODE -ne 0 -or $changes) { throw 'Build from a clean checkout.' }
    if ((dotnet --version) -cne $dotnetSdk -or $LASTEXITCODE -ne 0) {
        throw "Select .NET SDK $dotnetSdk on PATH."
    }
    if (Test-Path -LiteralPath $output) { throw 'Choose a new build output directory.' }

    $inputDirectory = Join-Path $output 'inputs'
    $null = New-Item -ItemType Directory -Path $inputDirectory
    if (-not $TorArchive) {
        $TorArchive = Join-Path $inputDirectory 'tor-expert-bundle-windows-x86_64-16.0.tar.gz'
        Invoke-WebRequest -Uri 'https://dist.torproject.org/torbrowser/16.0/tor-expert-bundle-windows-x86_64-16.0.tar.gz' `
            -OutFile $TorArchive -TimeoutSec 120
    }
    $actual = (Get-FileHash -LiteralPath $TorArchive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -cne $torSha256) { throw 'Tor archive SHA-256 mismatch.' }
    $tor = Join-Path $inputDirectory 'tor'
    $null = New-Item -ItemType Directory -Path $tor
    tar -xf $TorArchive -C $tor
    if ($LASTEXITCODE -ne 0) { throw 'Tor archive extraction failed.' }

    $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
    $rustFlags = @('-C', 'link-arg=/Brepro')
    foreach ($path in @(@($repository, '/_/src'), @($cargoHome, '/_/cargo'))) {
        foreach ($prefix in @($path[0].Replace('\', '/'), $path[0].Replace('/', '\')) | Select-Object -Unique) {
            $rustFlags += '--remap-path-prefix', "$prefix=$($path[1])"
        }
    }
    $env:RUSTUP_TOOLCHAIN = $toolchain
    $env:CARGO_ENCODED_RUSTFLAGS = $rustFlags -join [char]0x1f
    $env:CARGO_INCREMENTAL = '0'
    $env:CARGO_TARGET_DIR = Join-Path $output 'cargo-target'
    $env:ContinuousIntegrationBuild = 'true'
    $env:PathMap = "$repository=/_/src"
    $env:RuntimeFrameworkVersion = $dotnetRuntime

    $rust = rustc -vV
    if ($LASTEXITCODE -ne 0) { throw "Install the Rust $toolchain toolchain." }
    if (-not $env:VCToolsInstallDir -or -not $env:WindowsSDKVersion) {
        throw 'Start PowerShell in an x64 Visual Studio developer environment.'
    }
    $linker = Get-Item -LiteralPath (Join-Path $env:VCToolsInstallDir 'bin/Hostx64/x64/link.exe')
    $linkerVersion = $linker.VersionInfo.FileVersion
    $env:CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER = $linker.FullName

    $paths = @{
        'KryptoCore-Container.exe' = 'container'
        'KryptoCore-MSG.exe' = 'msg'
        'KryptoCore-Rescue.exe' = 'rescue'
    }
    $builds = Join-Path $output 'builds'
    & "$PSScriptRoot/../container/build-windows.ps1" -OutputDirectory "$builds/container"
    & "$PSScriptRoot/../msg/build-windows.ps1" -TorBundleRoot $tor -OutputDirectory "$builds/msg"
    & "$PSScriptRoot/../rescue/build-windows.ps1" -OutputDirectory "$builds/rescue"
    $artifacts = Join-Path $output 'artifacts'
    $null = New-Item -ItemType Directory -Path $artifacts
    $files = foreach ($name in ($paths.Keys | Sort-Object)) {
        $exe = Get-Item -LiteralPath (Join-Path $builds "$($paths[$name])/$name")
        Copy-Item -LiteralPath $exe.FullName -Destination $artifacts
        @{
            name = $name
            size = $exe.Length
            sha256 = (Get-FileHash -LiteralPath $exe.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    @{
        source_commit = $source
        cargo_lock_sha256 = (Get-FileHash -LiteralPath Cargo.lock -Algorithm SHA256).Hash.ToLowerInvariant()
        tor_archive_sha256 = $torSha256
        rustc = $rust -join "`n"
        dotnet_sdk = $dotnetSdk
        dotnet_runtime = $dotnetRuntime
        msvc_linker = $linkerVersion
        windows_sdk = $env:WindowsSDKVersion.TrimEnd('\')
        runner_image = $env:ImageVersion
        files = @($files)
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $artifacts 'BUILD.json') -Encoding utf8
}
finally {
    Pop-Location
}
