$ErrorActionPreference = "Stop"
if ($PSVersionTable.PSVersion.Major -ge 7) { $PSNativeCommandUseErrorActionPreference = $true }
Set-Location (Join-Path $PSScriptRoot "..")

function Invoke-Checked {
    param([Parameter(Mandatory=$true)][scriptblock]$Command)
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "native command failed with exit code $LASTEXITCODE" }
}

$ValidationDir = "target/uniflow-validation"
$SmokeDir = "$ValidationDir/smoke"
Remove-Item -Recurse -Force $ValidationDir, "dist" -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $SmokeDir | Out-Null

Invoke-Checked { cargo fmt --all -- --check }
Invoke-Checked { python scripts/static_check.py }
Invoke-Checked { python scripts/validate-baseline.py }
Invoke-Checked { cargo check --locked --workspace --all-targets --all-features }
Invoke-Checked { python scripts/run_with_timeout.py 90 cargo test --locked -p uniflow-value-flow contextual_function_heap_effect_summary_carries_context_metadata -- --nocapture }
Invoke-Checked { python scripts/run_with_timeout.py 1200 cargo test --locked --workspace --all-features --no-fail-fast }
Invoke-Checked { cargo build --locked --release -p uniflow-cli --bin uniflow }

$Bin = "target/release/uniflow.exe"
& $Bin --version | Set-Content "$SmokeDir/version.txt"
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Quiet -Pattern '^uniflow 1\.0\.0$' "$SmokeDir/version.txt")) { throw "version smoke failed" }

& $Bin analyze-source --language c --input examples/smoke/command_flow.c --use-default-models --pretty-findings --sarif-out "$SmokeDir/c.sarif.json" --dot-out "$SmokeDir/c.dot" --markdown-out "$SmokeDir/c.md" | Set-Content "$SmokeDir/c.txt"
if ($LASTEXITCODE -ne 0) { throw "C smoke command failed" }
if (-not (Select-String -Quiet -Pattern 'source_rule: c-getenv' "$SmokeDir/c.txt")) { throw "C source smoke failed" }
if (-not (Select-String -Quiet -Pattern 'sink_rule: c-system' "$SmokeDir/c.txt")) { throw "C sink smoke failed" }

& $Bin analyze-source --language cpp --input examples/smoke/command_flow.cpp --use-default-models --pretty-findings | Set-Content "$SmokeDir/cpp.txt"
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Quiet -Pattern 'sink_rule: c-system' "$SmokeDir/cpp.txt")) { throw "C++ smoke failed" }

& $Bin analyze-project --language java --input examples/smoke/java_project --use-default-models --pretty-findings | Set-Content "$SmokeDir/java.txt"
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Quiet -Pattern 'sink_rule: java-sql-statement-executequery' "$SmokeDir/java.txt")) { throw "Java smoke failed" }

& $Bin analyze-project --language python --input examples/smoke/python_project --use-default-models --cache-out "$SmokeDir/python-cache.json" --pretty-findings | Set-Content "$SmokeDir/python.txt"
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Quiet -Pattern 'sink_rule: python-os-system' "$SmokeDir/python.txt")) { throw "Python smoke failed" }

& $Bin analyze-project --language python --input examples/smoke/python_project --use-default-models --cache-in "$SmokeDir/python-cache.json" --dump-cache-plan --pretty-findings | Set-Content "$SmokeDir/python-cached.txt"
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Quiet -Pattern '"reused": \[' "$SmokeDir/python-cached.txt")) { throw "cache reuse smoke failed" }

& $Bin analyze-source --language c --platform windows-x86_64-msvc --input examples/platform_profiles/demo.c --use-default-models --dump-hir --pretty-findings | Set-Content "$SmokeDir/platform-windows.txt"
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Quiet -Pattern 'COMSPEC' "$SmokeDir/platform-windows.txt") -or (Select-String -Quiet -Pattern 'SHELL' "$SmokeDir/platform-windows.txt")) { throw "Windows profile smoke failed" }

& $Bin analyze-source --language c --platform linux-x86_64-gnu --input examples/platform_profiles/demo.c --use-default-models --dump-hir --pretty-findings | Set-Content "$SmokeDir/platform-linux.txt"
if ($LASTEXITCODE -ne 0 -or -not (Select-String -Quiet -Pattern 'SHELL' "$SmokeDir/platform-linux.txt") -or (Select-String -Quiet -Pattern 'COMSPEC' "$SmokeDir/platform-linux.txt")) { throw "Linux profile smoke failed" }

& $Bin list-rule-packs | Set-Content "$SmokeDir/model-manifest.json"
& $Bin list-baseline-packs | Set-Content "$SmokeDir/baseline-manifest.json"
Invoke-Checked { $Bin dump-mit-rules --language python --output "$SmokeDir/python-mit-rules.yml" }
Invoke-Checked { $Bin check-rules --rules "$SmokeDir/python-mit-rules.yml" }

foreach ($Language in @("c", "cpp", "java", "python")) {
    Invoke-Checked { $Bin check-baseline --language $Language --input "examples/baseline_smoke/$Language" --json-out "$SmokeDir/baseline-$Language.json" }
    Invoke-Checked { python scripts/validate-baseline-output.py $Language "$SmokeDir/baseline-$Language.json" }
}
Invoke-Checked { python scripts/validate-sarif.py "$SmokeDir/c.sarif.json" }
Invoke-Checked { python scripts/parser-fuzz-smoke.py --bin $Bin --timeout 10 }
Invoke-Checked { python scripts/run-quality-corpus.py --bin $Bin --output "$ValidationDir/quality-corpus.json" }
Invoke-Checked { python scripts/performance-budget.py --bin $Bin --output "$ValidationDir/performance.json" }

# Full Rust/C/C++ checker ABI v1/v2 and negative-fixture coverage.
Invoke-Checked { & .\scripts\validate-checker-sdk.ps1 }
Get-ChildItem target/checker-sdk-validation/*.sarif | ForEach-Object {
    $SarifPath = $_.FullName
    Invoke-Checked { python scripts/validate-sarif.py $SarifPath }
}

$HostTarget = ((rustc -vV | Select-String '^host: ').ToString() -replace '^host: ', '')
$Summary = @{
    product = "uniflow"; version = "1.0.0"; rust_toolchain = "1.97.1";
    host_target = $HostTarget; status = "passed";
    gates = @("format", "static", "all-targets-all-features-check", "workspace-tests", "release-build", "four-language-smoke", "cache", "platform-profiles", "baseline-200", "sarif", "checker-sdk-rust-c-cpp", "parser-mutation", "quality-corpus", "performance-memory-budget")
}
$Summary | ConvertTo-Json -Depth 4 | Set-Content "$ValidationDir/validation-summary.json"
Invoke-Checked { python scripts/package-release.py --bin $Bin --target $HostTarget --out-dir dist --format zip }
Write-Output "verification ok"
