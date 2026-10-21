Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$bootstrapRoot = $null
$tempBase = $null
if ($args.Count -lt 5) {
    [Console]::Error.WriteLine('provider-documentation-factory-release bootstrap: failed')
    exit 1
}
$SourceRoot = [string]$args[0]
$Commit = [string]$args[1]
$GoExecutable = [string]$args[2]
$GitExecutable = [string]$args[3]
if ([string]$args[4] -ne '--') {
    [Console]::Error.WriteLine('provider-documentation-factory-release bootstrap: failed')
    exit 1
}
$FactoryArguments = @($args | Select-Object -Skip 5)

function Fail-ReleaseBootstrap {
    [Console]::Error.WriteLine('provider-documentation-factory-release bootstrap: failed')
    exit 1
}

function New-ClosedProcessStartInfo {
    param([string]$Executable, [string[]]$Arguments, [string]$BootstrapRoot)
    $info = [System.Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Executable
    $info.UseShellExecute = $false
    foreach ($argument in $Arguments) { [void]$info.ArgumentList.Add($argument) }
    $info.Environment.Clear()
    $systemDirectory = [Environment]::SystemDirectory
    $systemRoot = [IO.Directory]::GetParent($systemDirectory).FullName
    $info.Environment['SystemRoot'] = $systemRoot
    $info.Environment['WINDIR'] = $systemRoot
    $info.Environment['PATHEXT'] = '.EXE'
    $info.Environment['HOME'] = [IO.Path]::Combine($BootstrapRoot, 'home')
    $info.Environment['USERPROFILE'] = [IO.Path]::Combine($BootstrapRoot, 'home')
    $info.Environment['PATH'] = [IO.Path]::Combine($BootstrapRoot, 'bin')
    $info.Environment['LANG'] = 'C'
    $info.Environment['LC_ALL'] = 'C'
    $info.Environment['TZ'] = 'UTC'
    $info.Environment['SOURCE_DATE_EPOCH'] = '0'
    $info.Environment['TMP'] = [IO.Path]::Combine($BootstrapRoot, 'tmp')
    $info.Environment['TEMP'] = [IO.Path]::Combine($BootstrapRoot, 'tmp')
    $info.Environment['TMPDIR'] = [IO.Path]::Combine($BootstrapRoot, 'tmp')
    $info.Environment['XDG_CACHE_HOME'] = [IO.Path]::Combine($BootstrapRoot, 'cache')
    $info.Environment['XDG_CONFIG_HOME'] = [IO.Path]::Combine($BootstrapRoot, 'config')
    $info.Environment['CGO_ENABLED'] = '0'
    $info.Environment['GO_EXTLINK_ENABLED'] = '0'
    $info.Environment['GO111MODULE'] = 'off'
    $info.Environment['GOENV'] = 'off'
    $info.Environment['GOWORK'] = 'off'
    $info.Environment['GOTOOLCHAIN'] = 'local'
    $info.Environment['GOFLAGS'] = ''
    $info.Environment['GOCACHE'] = [IO.Path]::Combine($BootstrapRoot, 'cache')
    $info.Environment['GOMODCACHE'] = [IO.Path]::Combine($BootstrapRoot, 'modcache')
    $info.Environment['GOPATH'] = [IO.Path]::Combine($BootstrapRoot, 'gopath')
    $info.Environment['GOTMPDIR'] = [IO.Path]::Combine($BootstrapRoot, 'gotmp')
    $info.Environment['GIT_CONFIG_NOSYSTEM'] = '1'
    $info.Environment['GIT_CONFIG_GLOBAL'] = [IO.Path]::Combine($BootstrapRoot, 'config', 'gitconfig')
    $info.Environment['GIT_TERMINAL_PROMPT'] = '0'
    $info.Environment['GIT_NO_REPLACE_OBJECTS'] = '1'
    $info.Environment['GIT_ASKPASS'] = ''
    $info.Environment['SSH_ASKPASS'] = ''
    $info.Environment['GCM_INTERACTIVE'] = 'never'
    return $info
}

function Invoke-ClosedCapturedProcess {
    param([string]$Executable, [string[]]$Arguments, [string]$BootstrapRoot, [string]$StdoutPath)
    $info = New-ClosedProcessStartInfo $Executable $Arguments $BootstrapRoot
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $info
    if (-not $process.Start()) { throw 'process start failed' }
    $target = $null
    try {
        if ($StdoutPath) {
            $target = [IO.File]::Open($StdoutPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $process.StandardOutput.BaseStream.CopyTo($target)
        } else {
            $null = $process.StandardOutput.ReadToEnd()
        }
        $null = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) { throw 'process failed' }
    } finally {
        if ($target) { $target.Dispose() }
        $process.Dispose()
    }
}

try {
    if ($Commit -cnotmatch '^[0-9a-f]{40}$') { Fail-ReleaseBootstrap }
    if (-not [IO.Path]::IsPathFullyQualified($SourceRoot) -or -not [IO.Path]::IsPathFullyQualified($GoExecutable) -or -not [IO.Path]::IsPathFullyQualified($GitExecutable)) { Fail-ReleaseBootstrap }
    $SourceRoot = [IO.Path]::GetFullPath($SourceRoot)
    $GoExecutable = [IO.Path]::GetFullPath($GoExecutable)
    $GitExecutable = [IO.Path]::GetFullPath($GitExecutable)
    if (-not [IO.Directory]::Exists($SourceRoot) -or -not [IO.File]::Exists($GoExecutable) -or -not [IO.File]::Exists($GitExecutable)) { Fail-ReleaseBootstrap }

    $tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    $bootstrapRoot = [IO.Path]::Combine($tempBase, 'velenza-provider-factory-bootstrap-' + [Guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($bootstrapRoot)
    foreach ($name in @('home', 'cache', 'modcache', 'gopath', 'gotmp', 'tmp', 'config', 'bin')) { [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($bootstrapRoot, $name)) }
    [IO.File]::WriteAllBytes([IO.Path]::Combine($bootstrapRoot, 'config', 'gitconfig'), [byte[]]@())
    $launcher = [IO.Path]::Combine($bootstrapRoot, 'provider-documentation-factory-release.go')
    $platformLauncher = [IO.Path]::Combine($bootstrapRoot, 'child_process_windows.go')
    $receiptPublisher = [IO.Path]::Combine($bootstrapRoot, 'receipt_publish_windows.go')

    $replaceInfo = New-ClosedProcessStartInfo $GitExecutable @('-C', $SourceRoot, 'for-each-ref', '--format=%(refname)', 'refs/replace') $bootstrapRoot
    $replaceInfo.RedirectStandardOutput = $true
    $replaceInfo.RedirectStandardError = $true
    $replaceProcess = [Diagnostics.Process]::Start($replaceInfo)
    $replaceOutput = $replaceProcess.StandardOutput.ReadToEnd()
    $null = $replaceProcess.StandardError.ReadToEnd()
    $replaceProcess.WaitForExit()
    if ($replaceProcess.ExitCode -ne 0 -or -not [string]::IsNullOrWhiteSpace($replaceOutput)) { Fail-ReleaseBootstrap }
    $replaceProcess.Dispose()

    Invoke-ClosedCapturedProcess $GitExecutable @('-C', $SourceRoot, 'cat-file', '-e', ($Commit + '^{commit}')) $bootstrapRoot $null
    Invoke-ClosedCapturedProcess $GitExecutable @('-C', $SourceRoot, 'show', ($Commit + ':cmd/provider-documentation-factory-release/main.go')) $bootstrapRoot $launcher
    Invoke-ClosedCapturedProcess $GitExecutable @('-C', $SourceRoot, 'show', ($Commit + ':cmd/provider-documentation-factory-release/child_process_windows.go')) $bootstrapRoot $platformLauncher
    Invoke-ClosedCapturedProcess $GitExecutable @('-C', $SourceRoot, 'show', ($Commit + ':cmd/provider-documentation-factory-release/receipt_publish_windows.go')) $bootstrapRoot $receiptPublisher
    if ((Get-Item -LiteralPath $launcher).Length -le 0 -or (Get-Item -LiteralPath $platformLauncher).Length -le 0 -or (Get-Item -LiteralPath $receiptPublisher).Length -le 0) { Fail-ReleaseBootstrap }

    $goArguments = @('run', '-trimpath', $launcher, $platformLauncher, $receiptPublisher, '--source-root', $SourceRoot, '--commit', $Commit, '--go-executable', $GoExecutable, '--git-executable', $GitExecutable, '--') + $FactoryArguments
    $goInfo = New-ClosedProcessStartInfo $GoExecutable $goArguments $bootstrapRoot
    $goProcess = [Diagnostics.Process]::Start($goInfo)
    $goProcess.WaitForExit()
    $exitCode = $goProcess.ExitCode
    $goProcess.Dispose()
    exit $exitCode
} catch {
    Fail-ReleaseBootstrap
} finally {
    if ($bootstrapRoot -and $tempBase -and $bootstrapRoot.StartsWith([IO.Path]::Combine($tempBase, 'velenza-provider-factory-bootstrap-'), [StringComparison]::OrdinalIgnoreCase) -and [IO.Directory]::Exists($bootstrapRoot)) {
        Remove-Item -LiteralPath $bootstrapRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
