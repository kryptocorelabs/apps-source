[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Container','Msg','Rescue','Vault')][string]$Product,
    [Parameter(Mandatory)][string]$Executable,
    [string]$OutputDirectory = 'dist/portable-checks'
)

$ErrorActionPreference='Stop'
$source=(Resolve-Path -LiteralPath $Executable).Path
$output=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$null=New-Item -ItemType Directory -Force -Path $output
$output=(Resolve-Path -LiteralPath $output).Path
$scratch=Join-Path $output ("$($Product.ToLowerInvariant())-"+[Guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $scratch
$app=Join-Path $scratch 'app'
$null=New-Item -ItemType Directory -Path $app
$copy=Join-Path $app ([IO.Path]::GetFileName($source))
Copy-Item -LiteralPath $source -Destination $copy
$hash=(Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant()

# Inspect the PE header: Windows x64 GUI, not a console launcher.
$stream=[IO.File]::OpenRead($copy)
$reader=[IO.BinaryReader]::new($stream)
try {
    if($reader.ReadUInt16() -ne 0x5A4D){throw 'Not a Windows executable.'}
    $stream.Position=0x3c;$pe=$reader.ReadInt32()
    if($pe -lt 64 -or $pe -gt $stream.Length-94){throw 'Invalid PE offset.'}
    $stream.Position=$pe
    if($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664){throw 'Expected Windows x64 executable.'}
    $stream.Position=$pe+24
    if($reader.ReadUInt16() -ne 0x20b){throw 'Expected PE32+ executable.'}
    $stream.Position=$pe+24+68
    if($reader.ReadUInt16() -ne 2){throw 'Expected GUI subsystem, not console.'}
} finally {$reader.Dispose()}

function Read-FirefoxRegistration {
    $key=[Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Mozilla\NativeMessagingHosts\com.kryptocorelabs.vault')
    if($null -eq $key){return @{exists=$false;value=$null}}
    try{return @{exists=$true;value=$key.GetValue('')}}finally{$key.Dispose()}
}
$before=if($Product -eq 'Vault'){Read-FirefoxRegistration}else{$null}
$checks=@()
foreach($argument in $(if($Product -eq 'Vault'){@('--verify-bundle')}elseif($Product -eq 'Msg'){@('--verify-package','--verify-tor-offline')}else{@('--verify-package')})){
    $name=$argument.TrimStart('-')
    $start=[Diagnostics.ProcessStartInfo]::new($copy)
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $start.WorkingDirectory=$app
    $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
    $start.ArgumentList.Add($argument)
    # The copied app has no workers, DLLs, configs or runtimes beside it.
    # Child processes inherit only OS tools on PATH and isolated writable dirs.
    $start.Environment['PATH']="$env:SystemRoot\System32;$env:SystemRoot"
    foreach($entry in @('PYTHONHOME','PYTHONPATH','VIRTUAL_ENV','QT_PLUGIN_PATH','QT_QPA_PLATFORM_PLUGIN_PATH','QML2_IMPORT_PATH','QT_QPA_PLATFORM')){
        $null=$start.Environment.Remove($entry)
    }
    $start.Environment['DOTNET_ROOT']=Join-Path $scratch 'no-installed-dotnet'
    $start.Environment['DOTNET_ROOT_X64']=$start.Environment['DOTNET_ROOT']
    $start.Environment['DOTNET_MULTILEVEL_LOOKUP']='0'
    foreach($entry in @('LOCALAPPDATA','APPDATA','TEMP','TMP','DOTNET_BUNDLE_EXTRACT_BASE_DIR')){
        $directory=Join-Path $scratch $entry.ToLowerInvariant()
        $null=New-Item -ItemType Directory -Force -Path $directory
        $start.Environment[$entry]=$directory
    }
    $watch=[Diagnostics.Stopwatch]::StartNew()
    $process=[Diagnostics.Process]::new();$process.StartInfo=$start
    try {
        if(-not $process.Start()){throw 'Process did not start.'}
        $stdout=$process.StandardOutput.ReadToEndAsync();$stderr=$process.StandardError.ReadToEndAsync()
        if(-not $process.WaitForExit(60000)){
            $process.Kill($true);$process.WaitForExit()
            throw "$Product $argument timed out. Test files retained at $scratch"
        }
        $watch.Stop()
        [IO.File]::WriteAllText((Join-Path $output "$($Product.ToLowerInvariant())-$name.stdout.log"),$stdout.GetAwaiter().GetResult())
        [IO.File]::WriteAllText((Join-Path $output "$($Product.ToLowerInvariant())-$name.stderr.log"),$stderr.GetAwaiter().GetResult())
        if($process.ExitCode -ne 0){throw "$Product $argument failed (exit $($process.ExitCode)). Test files retained at $scratch"}
        $checks+=@{argument=$argument;exit_code=$process.ExitCode;elapsed_ms=$watch.ElapsedMilliseconds}
    } finally {$process.Dispose()}
}
if(@(Get-ChildItem -LiteralPath $app -Force).Count -ne 1){throw 'Application required or created a sidecar beside the executable.'}
if((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash.ToLowerInvariant() -ne $hash){throw 'Executable changed during verification.'}
if($Product -eq 'Vault'){
    $after=Read-FirefoxRegistration
    if($before.exists -ne $after.exists -or $before.value -ne $after.value){throw 'Verification changed the normal Firefox native-host registration.'}
}
$report=@{schema_version=1;product=$Product;executable=[IO.Path]::GetFileName($source);sha256=$hash;
    executable_only=$true;gui_subsystem=$true;isolated_environment=$true;checks=$checks;
    clean_windows_vm_tested=$false;public_tor_delivery_tested=$false}
$report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $output "$($Product.ToLowerInvariant()).json") -Encoding utf8
# Delete only the fresh, checked child of the explicit test output directory.
$absolute=[IO.Path]::GetFullPath($scratch)
if(-not $absolute.StartsWith($output.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)){
    throw 'Refusing cleanup outside the test output directory.'
}
Remove-Item -LiteralPath $absolute -Recurse -Force
Write-Output "PASS ${Product}: executable-only Windows x64 GUI; isolated runtime checks completed."
