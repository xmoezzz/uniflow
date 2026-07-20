$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) { $PSNativeCommandUseErrorActionPreference = $false }
Set-Location (Join-Path $PSScriptRoot "..")

$Root = (Get-Location).Path
$ResultDir = Join-Path $Root "target/checker-sdk-validation"
$BuildDir = Join-Path $ResultDir "plugins"
$PluginManifest = Join-Path $Root "examples/checkers/banned_function_checker/Cargo.toml"
$RustPlugin = Join-Path $Root "examples/checkers/banned_function_checker/target/debug/uniflow_example_banned_function_checker.dll"
$Bin = Join-Path $Root "target/debug/uniflow.exe"
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
Get-ChildItem $ResultDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.out','.err','.sarif' } | Remove-Item -Force

function Find-Compiler([string]$Name) {
    $Command = Get-Command "$Name.exe" -ErrorAction SilentlyContinue
    if ($Command) { return $Command.Source }
    $Known = Join-Path $env:ProgramFiles "LLVM/bin/$Name.exe"
    if (Test-Path $Known) { return $Known }
    throw "$Name.exe is required for the Windows release checker gate"
}

$CC = Find-Compiler "clang"
$CXX = Find-Compiler "clang++"

function Invoke-Checked([string]$Program, [string[]]$Arguments) {
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" }
}

function Shared-Path([string]$Name) { Join-Path $BuildDir "$Name.dll" }

function Compile-C([string]$Output, [string[]]$Extra, [string]$Source) {
    $Args = @('-std=c11','-Wall','-Wextra','-Werror','-shared',"-I$Root/include") + $Extra + @($Source,'-o',$Output)
    Invoke-Checked $CC $Args
}

function Compile-Cpp([string]$Output, [string[]]$Extra, [string]$Source) {
    $Args = @('-std=c++17','-Wall','-Wextra','-Werror','-shared',"-I$Root/include") + $Extra + @($Source,'-o',$Output)
    Invoke-Checked $CXX $Args
}

function Compile-Fixture([string]$Name, [string]$Macro) {
    $Output = Shared-Path $Name
    Compile-C $Output @("-D$Macro") (Join-Path $Root 'examples/checkers/fixtures/checker_fixture.c')
    return $Output
}

Invoke-Checked 'cargo' @('build','--locked','-p','uniflow-cli','--bin','uniflow')
Invoke-Checked 'cargo' @('build','--manifest-path',$PluginManifest)

$CPlugin = Shared-Path 'c_banned_checker'
$CppPlugin = Shared-Path 'cpp_banned_checker'
$CV1Plugin = Shared-Path 'c_v1_checker'
$MissingSymbolPlugin = Shared-Path 'missing_symbol'
Compile-C $CPlugin @() (Join-Path $Root 'examples/checkers/c_banned_function_checker/checker.c')
Compile-Cpp $CppPlugin @() (Join-Path $Root 'examples/checkers/cpp_banned_function_checker/checker.cpp')
Compile-C $CV1Plugin @('-DCHECKER_V1_ONLY') (Join-Path $Root 'examples/checkers/c_banned_function_checker/checker.c')
Compile-C $MissingSymbolPlugin @() (Join-Path $Root 'examples/checkers/fixtures/missing_symbol.c')

$NullTablePlugin = Compile-Fixture 'null_table' 'FIXTURE_NULL_TABLE'
$WrongAbiPlugin = Compile-Fixture 'wrong_abi' 'FIXTURE_WRONG_ABI'
$TruncatedPlugin = Compile-Fixture 'truncated' 'FIXTURE_TRUNCATED_TABLE'
$NoCapabilityPlugin = Compile-Fixture 'no_capability' 'FIXTURE_NO_CAPABILITY'
$NullCallbackPlugin = Compile-Fixture 'null_callback' 'FIXTURE_NULL_CALLBACK'
$InvalidManifestPlugin = Compile-Fixture 'invalid_manifest' 'FIXTURE_INVALID_MANIFEST'
$WrongManifestAbiPlugin = Compile-Fixture 'wrong_manifest_abi' 'FIXTURE_WRONG_MANIFEST_ABI'
$EmptyIdPlugin = Compile-Fixture 'empty_id' 'FIXTURE_EMPTY_ID'
$DuplicateIdPlugin = Compile-Fixture 'duplicate_id' 'FIXTURE_DUPLICATE_ID'
$InvalidResponsePlugin = Compile-Fixture 'invalid_response' 'FIXTURE_INVALID_RESPONSE'
$ErrorResponsePlugin = Compile-Fixture 'error_response' 'FIXTURE_ERROR_RESPONSE'
$InvalidFindingPlugin = Compile-Fixture 'invalid_finding' 'FIXTURE_INVALID_FINDING'
$HangPlugin = Compile-Fixture 'hang' 'FIXTURE_HANG'
$CrashPlugin = Compile-Fixture 'crash' 'FIXTURE_CRASH'

function Run-Checker([string]$Name, [string[]]$CheckerArgs) {
    $Out = Join-Path $ResultDir "$Name.out"
    $Err = Join-Path $ResultDir "$Name.err"
    $Sarif = Join-Path $ResultDir "$Name.sarif"
    $Args = @('analyze-source','--language','c','--input','examples/checker_demo/demo.c','--checker-timeout-ms','750','--checker-isolation','process') + $CheckerArgs + @('--sarif-out',$Sarif)
    & $Bin @Args 1> $Out 2> $Err
    return $LASTEXITCODE
}

foreach ($Case in @(
    @{Name='rust'; Args=@('--checker',$RustPlugin)},
    @{Name='c'; Args=@('--checker',$CPlugin)},
    @{Name='cpp'; Args=@('--checker',$CppPlugin)},
    @{Name='c-v1'; Args=@('--checker',$CV1Plugin)},
    @{Name='combined'; Args=@('--checker',$RustPlugin,'--checker',$CPlugin,'--checker',$CppPlugin)}
)) {
    if ((Run-Checker $Case.Name $Case.Args) -ne 0) { throw "valid checker case failed: $($Case.Name)" }
}

$Expected = @{
    'rust' = @{'example.banned-function.dangerous-call'=1}
    'c' = @{'example.c-banned-function.dangerous-call'=1}
    'cpp' = @{'example.cpp-banned-function.dangerous-call'=1}
    'c-v1' = @{'example.c-banned-function.dangerous-call'=1}
    'combined' = @{
        'example.banned-function.dangerous-call'=1
        'example.c-banned-function.dangerous-call'=1
        'example.cpp-banned-function.dangerous-call'=1
    }
}
foreach ($Name in $Expected.Keys) {
    $Data = Get-Content (Join-Path $ResultDir "$Name.sarif") -Raw | ConvertFrom-Json
    $Counts = @{}
    foreach ($Result in $Data.runs[0].results) {
        $Rule = $Result.ruleId
        if (-not $Counts.ContainsKey($Rule)) { $Counts[$Rule] = 0 }
        $Counts[$Rule] += 1
        if (-not $Result.partialFingerprints.'uniflow/v1') { throw "$Name/$Rule missing fingerprint" }
        if (-not $Result.locations) { throw "$Name/$Rule missing location" }
    }
    foreach ($Rule in $Expected[$Name].Keys) {
        if ($Counts[$Rule] -ne $Expected[$Name][$Rule]) { throw "$Name has unexpected count for $Rule" }
    }
}

function Expect-Fail([string]$Name, [string]$Plugin, [string]$Pattern) {
    $Code = Run-Checker "negative-$Name" @('--checker',$Plugin)
    if ($Code -eq 0) { throw "negative checker fixture unexpectedly succeeded: $Name" }
    $ErrorText = Get-Content (Join-Path $ResultDir "negative-$Name.err") -Raw
    if ($ErrorText -notmatch $Pattern) { throw "negative checker fixture did not report expected diagnostic: $Name / $Pattern`n$ErrorText" }
}

Expect-Fail 'missing-symbol' $MissingSymbolPlugin 'exports neither|entry_v2|entry_v1'
Expect-Fail 'null-table' $NullTablePlugin 'null ABI v2 table'
Expect-Fail 'wrong-abi' $WrongAbiPlugin 'v2 entry returned ABI'
Expect-Fail 'truncated' $TruncatedPlugin 'truncated'
Expect-Fail 'no-capability' $NoCapabilityPlugin 'JSON event support'
Expect-Fail 'null-callback' $NullCallbackPlugin 'null manifest_json callback'
Expect-Fail 'invalid-manifest' $InvalidManifestPlugin 'manifest is not valid|invalid manifest'
Expect-Fail 'wrong-manifest-abi' $WrongManifestAbiPlugin 'manifest declares ABI'
Expect-Fail 'empty-id' $EmptyIdPlugin 'empty id'
Expect-Fail 'invalid-response' $InvalidResponsePlugin 'not valid CheckerResponse|invalid response|worker.*failed'
Expect-Fail 'error-response' $ErrorResponsePlugin 'fixture failure|worker.*failed'
Expect-Fail 'invalid-finding' $InvalidFindingPlugin 'invalid finding|empty rule id'
Expect-Fail 'hang' $HangPlugin 'timeout|exceeded'
Expect-Fail 'crash' $CrashPlugin 'terminated without a response|worker.*failed'

$DuplicateCode = Run-Checker 'negative-duplicate' @('--checker',$CPlugin,'--checker',$DuplicateIdPlugin)
if ($DuplicateCode -eq 0) { throw 'duplicate checker ID unexpectedly succeeded' }
if ((Get-Content (Join-Path $ResultDir 'negative-duplicate.err') -Raw) -notmatch 'duplicate checker id') { throw 'duplicate checker ID diagnostic missing' }

$ContinueCode = Run-Checker 'continue' @('--checker',$RustPlugin,'--checker',$InvalidResponsePlugin,'--checker-failure','continue')
if ($ContinueCode -ne 0) { throw 'continue-on-checker-error failed' }
if ((Get-Content (Join-Path $ResultDir 'continue.err') -Raw) -notmatch 'checker diagnostic:') { throw 'continue checker diagnostic missing' }
$Continue = Get-Content (Join-Path $ResultDir 'continue.sarif') -Raw | ConvertFrom-Json
if (-not ($Continue.runs[0].results | Where-Object { $_.ruleId -eq 'example.banned-function.dangerous-call' })) { throw 'valid checker result missing after continued failure' }

Write-Output 'checker SDK validation ok'
