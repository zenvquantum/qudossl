<#
.SYNOPSIS
    QudoSSL Windows build wrapper (MSVC / nmake).

.DESCRIPTION
    Windows equivalent of build/Makefile, in two stages:
      1. CMake builds qudo-pqc-lib into a static archive (math-only).
      2. OpenSSL is configured for VC-WIN64A and built with nmake.

    Run from an "x64 Native Tools Command Prompt for VS 2022", or any shell
    where cl.exe and nmake.exe are on PATH.

.PARAMETER Target
    all | qudo-pqc | openssl | test | clean

.PARAMETER Fips
    Build with enable-fips. Default true.

.EXAMPLE
    pwsh -File build\build.ps1 -Target all
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'qudo-pqc', 'openssl', 'test', 'clean')]
    [string]$Target = 'all',
    [bool]$Fips = $true
)

$ErrorActionPreference = 'Stop'

$RepoRoot     = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$OpenSslDir   = Join-Path $RepoRoot 'openssl'
$QudoPqcDir   = Join-Path $RepoRoot 'qudo-pqc-lib'
$QudoPqcBuild = Join-Path $QudoPqcDir 'build'
$Prefix       = Join-Path $RepoRoot 'build\out'

# Fixed epoch so two clean builds agree (see build/Makefile).
if (-not $env:SOURCE_DATE_EPOCH) { $env:SOURCE_DATE_EPOCH = '1752451200' }

function Assert-Tool([string]$Name, [string]$Hint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required tool '$Name' not found on PATH. $Hint"
    }
}

function Invoke-Checked([string]$Exe, [string[]]$Arguments, [string]$WorkDir) {
    Push-Location $WorkDir
    try {
        Write-Host "+ $Exe $($Arguments -join ' ')"
        # Stream stderr with stdout so tool diagnostics appear in the log.
        & $Exe @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
        if ($LASTEXITCODE -ne 0) {
            throw "$Exe $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
        }
    } finally {
        Pop-Location
    }
}

function Find-QudoArchive {
    # NMake Makefiles is single-config, so the archive is in <build>/lib; the
    # Release\ paths cover multi-config generators.
    $candidates = @(
        (Join-Path $QudoPqcBuild 'lib\qudo-pqc.lib'),
        (Join-Path $QudoPqcBuild 'lib\Release\qudo-pqc.lib'),
        (Join-Path $QudoPqcBuild 'Release\qudo-pqc.lib')
    )
    foreach ($c in $candidates) { if (Test-Path $c) { return $c } }
    $found = Get-ChildItem -Path $QudoPqcBuild -Recurse -Filter 'qudo-pqc*.lib' -ErrorAction SilentlyContinue |
             Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

function Build-QudoPqc {
    Write-Host '==> Stage 1: qudo-pqc-lib -> qudo-pqc.lib'
    Assert-Tool 'cmake' 'Install CMake >= 3.15.'

    # Math-only build; see build_libqudo_pqc.sh. qudo-pqc-lib is built with the
    # "NMake Makefiles" generator and needs an MSVC environment on PATH.
    #
    # CMake ignores unknown -D options, so check that QUDO_PQC_MATH_ONLY exists.
    $cml = Join-Path $QudoPqcDir 'CMakeLists.txt'
    if (-not (Select-String -Path $cml -Pattern 'QUDO_PQC_MATH_ONLY' -Quiet)) {
        throw @"
this qudo-pqc-lib does not support QUDO_PQC_MATH_ONLY.
Use a qudo-pqc-lib release that supports it (see docs/vendored-versions.md).
"@
    }

    $cmakeArgs = @(
        '-S', $QudoPqcDir,
        '-B', $QudoPqcBuild,
        '-G', 'NMake Makefiles',
        '-DCMAKE_BUILD_TYPE=Release',
        '-DBUILD_SHARED_LIBS=OFF',
        '-DQUDO_PQC_MATH_ONLY=ON',
        '-DQUDO_PQC_BUILD_TESTS=OFF'
    )
    Invoke-Checked 'cmake' $cmakeArgs $RepoRoot
    # Only the qudo-pqc target is built; QudoSSL does not use the standalone
    # sub-libraries.
    Invoke-Checked 'cmake' @('--build', $QudoPqcBuild, '--target', 'qudo-pqc') $RepoRoot

    $archive = Find-QudoArchive
    if (-not $archive) { throw "Stage 1 produced no qudo-pqc archive under $QudoPqcBuild" }
    Write-Host "==> Stage 1 complete: $archive"
    return $archive
}

function Build-OpenSsl {
    Write-Host '==> Stage 2: configuring OpenSSL (VC-WIN64A)'
    Assert-Tool 'perl' 'Install Strawberry Perl and put perl.exe on PATH.'
    Assert-Tool 'nmake' 'Run from a x64 Native Tools Command Prompt for VS 2022.'

    $cfg = @('Configure', 'VC-WIN64A', "--prefix=$Prefix")
    if ($Fips) { $cfg += 'enable-fips' }

    # Required for delegation: without these, Configure does not define
    # QUDO_PQC_DELEGATE and builds upstream ML-KEM/ML-DSA.
    $archive = Find-QudoArchive
    if (-not $archive) {
        throw "no qudo-pqc archive under $QudoPqcBuild -- run stage 1 first (-Target all)."
    }
    $cfg += "--with-qudo-pqc-archive=$archive"
    foreach ($inc in @('include',
                       'qudo-mlkem\include',
                       'qudo-mldsa\include')) {
        $cfg += "--with-qudo-pqc-include=$(Join-Path $QudoPqcDir $inc)"
    }

    # /Brepro requests a deterministic PE (no timestamp). Windows
    # reproducibility is not verified; see docs/reproducibility.md.
    $cfg += '/Brepro'

    Invoke-Checked 'perl' $cfg $OpenSslDir

    Write-Host '==> Stage 2: building OpenSSL'
    Invoke-Checked 'nmake' @() $OpenSslDir

    Write-Host '==> Build complete:'
    Get-ChildItem -Path $OpenSslDir -Filter 'libcrypto*' -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "    $($_.Name)" }
    Get-ChildItem -Path (Join-Path $OpenSslDir 'providers') -Filter 'fips.dll' -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "    providers\$($_.Name)" }
}

switch ($Target) {
    'qudo-pqc' { Build-QudoPqc | Out-Null }
    'openssl'  { Build-OpenSsl }
    'all'      { Build-QudoPqc | Out-Null; Build-OpenSsl }
    'test'     {
        Build-QudoPqc | Out-Null
        Build-OpenSsl
        Invoke-Checked 'nmake' @('test') $OpenSslDir
    }
    'clean'    {
        if (Test-Path $QudoPqcBuild) { Remove-Item -Recurse -Force $QudoPqcBuild }
        if (Test-Path $Prefix)       { Remove-Item -Recurse -Force $Prefix }
        if (Test-Path (Join-Path $OpenSslDir 'makefile')) {
            Invoke-Checked 'nmake' @('clean') $OpenSslDir
        }
    }
}
