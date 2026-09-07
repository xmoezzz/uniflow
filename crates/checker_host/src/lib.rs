use anyhow::{anyhow, bail, Context, Result};
use libloading::{Library, Symbol};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::{c_char, c_void, CStr};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};
use uniflow_checker_api::{
    capability, CheckerCreateFn, CheckerDestroyFn, CheckerEntryV1, CheckerEntryV2, CheckerEvent,
    CheckerFinding, CheckerFreeStringFn, CheckerKind, CheckerManifest, CheckerManifestJsonFn,
    CheckerOnEventJsonFn, CheckerResponse, UniflowCheckerV1, UniflowCheckerV2,
    CHECKER_ABI_VERSION_V1, CHECKER_ABI_VERSION_V2, CHECKER_ENTRY_SYMBOL_V1,
    CHECKER_ENTRY_SYMBOL_V2,
};

const IPC_PREFIX: &str = "UNIFLOW_CHECKER_IPC_V1\t";
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckerIsolation {
    /// Execute the checker in a dedicated UniFlow worker process. This contains
    /// panics, aborts, invalid memory accesses, and infinite loops.
    Process,
    /// Execute directly in the analyzer process. Intended only for trusted
    /// plugins and host-level tests.
    InProcess,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckerFailurePolicy {
    FailFast,
    Continue,
}

#[derive(Clone, Debug)]
pub struct CheckerHostOptions {
    pub isolation: CheckerIsolation,
    pub timeout: Duration,
    pub failure_policy: CheckerFailurePolicy,
}

impl Default for CheckerHostOptions {
    fn default() -> Self {
        Self {
            isolation: CheckerIsolation::Process,
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            failure_policy: CheckerFailurePolicy::FailFast,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CheckerDiagnostic {
    pub path: String,
    pub checker_id: Option<String>,
    pub event_kind: Option<String>,
    pub message: String,
}

pub struct CheckerManager {
    checkers: Vec<ManagedChecker>,
    next_sequence: u64,
    options: CheckerHostOptions,
    diagnostics: Vec<CheckerDiagnostic>,
    seen_fingerprints: HashSet<String>,
}

impl CheckerManager {
    pub fn load(paths: &[String]) -> Result<Self> {
        Self::load_with_options(paths, CheckerHostOptions::default())
    }

    pub fn load_with_options(paths: &[String], options: CheckerHostOptions) -> Result<Self> {
        let mut manager = Self {
            checkers: Vec::with_capacity(paths.len()),
            next_sequence: 0,
            options,
            diagnostics: Vec::new(),
            seen_fingerprints: HashSet::new(),
        };
        let mut checker_ids = HashSet::new();
        for path in paths {
            let result = ManagedChecker::load(Path::new(path), &manager.options);
            let checker = match result {
                Ok(checker) => checker,
                Err(error) => {
                    if manager.options.failure_policy == CheckerFailurePolicy::FailFast {
                        return Err(error);
                    }
                    manager.diagnostics.push(CheckerDiagnostic {
                        path: path.clone(),
                        checker_id: None,
                        event_kind: None,
                        message: format!("failed to load checker: {error:#}"),
                    });
                    continue;
                }
            };
            if !checker_ids.insert(checker.manifest.id.clone()) {
                let message = format!("duplicate checker id '{}'", checker.manifest.id);
                if manager.options.failure_policy == CheckerFailurePolicy::FailFast {
                    bail!(message);
                }
                manager.diagnostics.push(CheckerDiagnostic {
                    path: checker.path.display().to_string(),
                    checker_id: Some(checker.manifest.id.clone()),
                    event_kind: None,
                    message,
                });
                continue;
            }
            manager.checkers.push(checker);
        }
        Ok(manager)
    }

    pub fn is_empty(&self) -> bool {
        self.checkers.iter().all(|checker| !checker.enabled)
    }

    pub fn manifests(&self) -> Vec<CheckerManifest> {
        self.checkers
            .iter()
            .filter(|checker| checker.enabled)
            .map(|checker| checker.manifest.clone())
            .collect()
    }

    pub fn diagnostics(&self) -> &[CheckerDiagnostic] {
        &self.diagnostics
    }

    pub fn take_diagnostics(&mut self) -> Vec<CheckerDiagnostic> {
        std::mem::take(&mut self.diagnostics)
    }

    pub fn broadcast(&mut self, kind: &str, payload: Value) -> Result<Vec<CheckerFinding>> {
        let event = CheckerEvent {
            kind: kind.to_string(),
            sequence: self.next_sequence,
            payload,
        };
        self.next_sequence = self.next_sequence.saturating_add(1);

        let mut findings = Vec::new();
        for checker in &mut self.checkers {
            if !checker.enabled || !checker.manifest.subscribes_to(kind) {
                continue;
            }
            let produced = checker.handle_event(&event, self.options.timeout);
            let mut produced = match produced {
                Ok(produced) => produced,
                Err(error) => {
                    checker.enabled = false;
                    if self.options.failure_policy == CheckerFailurePolicy::FailFast {
                        return Err(error);
                    }
                    self.diagnostics.push(CheckerDiagnostic {
                        path: checker.path.display().to_string(),
                        checker_id: Some(checker.manifest.id.clone()),
                        event_kind: Some(kind.to_string()),
                        message: format!("checker disabled after failure: {error:#}"),
                    });
                    continue;
                }
            };
            for finding in &mut produced {
                if let Err(error) = validate_finding(&checker.manifest, finding) {
                    checker.enabled = false;
                    if self.options.failure_policy == CheckerFailurePolicy::FailFast {
                        return Err(error).with_context(|| {
                            format!(
                                "checker {} returned an invalid finding",
                                checker.manifest.id
                            )
                        });
                    }
                    self.diagnostics.push(CheckerDiagnostic {
                        path: checker.path.display().to_string(),
                        checker_id: Some(checker.manifest.id.clone()),
                        event_kind: Some(kind.to_string()),
                        message: format!("checker disabled after invalid finding: {error:#}"),
                    });
                    produced.clear();
                    break;
                }
                normalize_finding(&checker.manifest, finding);
            }
            for finding in produced {
                let fingerprint = finding.fingerprint.clone().unwrap_or_default();
                if fingerprint.is_empty() || self.seen_fingerprints.insert(fingerprint) {
                    findings.push(finding);
                }
            }
        }
        Ok(findings)
    }
}

struct ManagedChecker {
    path: PathBuf,
    manifest: CheckerManifest,
    backend: CheckerBackend,
    enabled: bool,
}

impl ManagedChecker {
    fn load(path: &Path, options: &CheckerHostOptions) -> Result<Self> {
        let canonical = path
            .canonicalize()
            .with_context(|| format!("checker library does not exist: {}", path.display()))?;
        let backend = match options.isolation {
            CheckerIsolation::InProcess => {
                CheckerBackend::InProcess(LoadedChecker::load(&canonical)?)
            }
            CheckerIsolation::Process => {
                CheckerBackend::Process(WorkerChecker::spawn(&canonical, options.timeout)?)
            }
        };
        let manifest = backend.manifest().clone();
        Ok(Self {
            path: canonical,
            manifest,
            backend,
            enabled: true,
        })
    }

    fn handle_event(
        &mut self,
        event: &CheckerEvent,
        timeout: Duration,
    ) -> Result<Vec<CheckerFinding>> {
        self.backend.handle_event(event, timeout)
    }
}

enum CheckerBackend {
    InProcess(LoadedChecker),
    Process(WorkerChecker),
}

impl CheckerBackend {
    fn manifest(&self) -> &CheckerManifest {
        match self {
            Self::InProcess(checker) => &checker.manifest,
            Self::Process(checker) => &checker.manifest,
        }
    }

    fn handle_event(
        &mut self,
        event: &CheckerEvent,
        timeout: Duration,
    ) -> Result<Vec<CheckerFinding>> {
        match self {
            Self::InProcess(checker) => checker.handle_event(event),
            Self::Process(checker) => checker.handle_event(event, timeout),
        }
    }
}

#[derive(Clone, Copy)]
struct PluginCallbacks {
    manifest_json: CheckerManifestJsonFn,
    create: CheckerCreateFn,
    on_event_json: CheckerOnEventJsonFn,
    destroy: CheckerDestroyFn,
    free_string: CheckerFreeStringFn,
}

struct LoadedChecker {
    path: PathBuf,
    manifest: CheckerManifest,
    callbacks: PluginCallbacks,
    instance: *mut c_void,
    _library: Library,
}

impl LoadedChecker {
    fn load(path: &Path) -> Result<Self> {
        let canonical = path
            .canonicalize()
            .with_context(|| format!("checker library does not exist: {}", path.display()))?;
        let library = unsafe { Library::new(&canonical) }
            .with_context(|| format!("failed to load checker library {}", canonical.display()))?;

        let (abi_version, callbacks) = unsafe { load_callbacks(&library, &canonical) }?;
        let manifest_text =
            unsafe { take_plugin_string((callbacks.manifest_json)(), callbacks.free_string) }
                .with_context(|| {
                    format!(
                        "checker {} returned an invalid manifest",
                        canonical.display()
                    )
                })?;
        let manifest: CheckerManifest =
            serde_json::from_str(&manifest_text).with_context(|| {
                format!(
                    "checker {} manifest is not valid CheckerManifest JSON: {}",
                    canonical.display(),
                    manifest_text
                )
            })?;
        validate_manifest(&manifest, abi_version, &canonical)?;

        let instance = unsafe { (callbacks.create)() };
        if instance.is_null() {
            bail!(
                "checker {} ({}) failed to create an instance",
                manifest.id,
                canonical.display()
            );
        }

        Ok(Self {
            path: canonical,
            manifest,
            callbacks,
            instance,
            _library: library,
        })
    }

    fn handle_event(&mut self, event: &CheckerEvent) -> Result<Vec<CheckerFinding>> {
        let event_json =
            serde_json::to_string(event).context("failed to serialize checker event")?;
        let event_c = std::ffi::CString::new(event_json)
            .map_err(|_| anyhow!("checker event contains an interior NUL byte"))?;
        let response_text = unsafe {
            take_plugin_string(
                (self.callbacks.on_event_json)(self.instance, event_c.as_ptr()),
                self.callbacks.free_string,
            )
        }
        .with_context(|| {
            format!(
                "checker {} ({}) returned an invalid response for event {}",
                self.manifest.id,
                self.path.display(),
                event.kind
            )
        })?;
        let response: CheckerResponse =
            serde_json::from_str(&response_text).with_context(|| {
                format!(
                    "checker {} response is not valid CheckerResponse JSON: {}",
                    self.manifest.id, response_text
                )
            })?;
        if let Some(error) = response.error {
            bail!(
                "checker {} failed while handling {}: {}",
                self.manifest.id,
                event.kind,
                error
            );
        }
        Ok(response.findings)
    }
}

impl Drop for LoadedChecker {
    fn drop(&mut self) {
        if !self.instance.is_null() {
            unsafe { (self.callbacks.destroy)(self.instance) };
            self.instance = std::ptr::null_mut();
        }
    }
}

unsafe fn load_callbacks(library: &Library, path: &Path) -> Result<(u32, PluginCallbacks)> {
    if let Ok(entry) = unsafe { library.get::<CheckerEntryV2>(CHECKER_ENTRY_SYMBOL_V2) } {
        return unsafe { load_callbacks_v2(*entry, path) };
    }
    let entry: Symbol<CheckerEntryV1> = unsafe { library.get(CHECKER_ENTRY_SYMBOL_V1) }
        .with_context(|| {
            format!(
                "checker {} exports neither uniflow_checker_entry_v2 nor uniflow_checker_entry_v1",
                path.display()
            )
        })?;
    unsafe { load_callbacks_v1(*entry, path) }
}

unsafe fn load_callbacks_v1(entry: CheckerEntryV1, path: &Path) -> Result<(u32, PluginCallbacks)> {
    let api = unsafe { entry() };
    if api.is_null() {
        bail!("checker {} returned a null ABI v1 table", path.display());
    }
    let api_ref: &UniflowCheckerV1 = unsafe { &*api };
    if api_ref.abi_version != CHECKER_ABI_VERSION_V1 {
        bail!(
            "checker {} v1 entry returned ABI {}",
            path.display(),
            api_ref.abi_version
        );
    }
    Ok((
        CHECKER_ABI_VERSION_V1,
        PluginCallbacks {
            manifest_json: required_callback(api_ref.manifest_json, "manifest_json", path)?,
            create: required_callback(api_ref.create, "create", path)?,
            on_event_json: required_callback(api_ref.on_event_json, "on_event_json", path)?,
            destroy: required_callback(api_ref.destroy, "destroy", path)?,
            free_string: required_callback(api_ref.free_string, "free_string", path)?,
        },
    ))
}

unsafe fn load_callbacks_v2(entry: CheckerEntryV2, path: &Path) -> Result<(u32, PluginCallbacks)> {
    let api = unsafe { entry() };
    if api.is_null() {
        bail!("checker {} returned a null ABI v2 table", path.display());
    }
    let api_ref: &UniflowCheckerV2 = unsafe { &*api };
    if api_ref.abi_version != CHECKER_ABI_VERSION_V2 {
        bail!(
            "checker {} v2 entry returned ABI {}",
            path.display(),
            api_ref.abi_version
        );
    }
    let required_size = std::mem::size_of::<UniflowCheckerV2>() as u64;
    if api_ref.struct_size < required_size {
        bail!(
            "checker {} ABI v2 table is truncated: {} bytes, need at least {}",
            path.display(),
            api_ref.struct_size,
            required_size
        );
    }
    if api_ref.capabilities & capability::JSON_EVENTS == 0 {
        bail!(
            "checker {} ABI v2 table does not declare JSON event support",
            path.display()
        );
    }
    Ok((
        CHECKER_ABI_VERSION_V2,
        PluginCallbacks {
            manifest_json: required_callback(api_ref.manifest_json, "manifest_json", path)?,
            create: required_callback(api_ref.create, "create", path)?,
            on_event_json: required_callback(api_ref.on_event_json, "on_event_json", path)?,
            destroy: required_callback(api_ref.destroy, "destroy", path)?,
            free_string: required_callback(api_ref.free_string, "free_string", path)?,
        },
    ))
}

fn required_callback<T: Copy>(callback: Option<T>, name: &str, path: &Path) -> Result<T> {
    callback.ok_or_else(|| anyhow!("checker {} has a null {} callback", path.display(), name))
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum WorkerRequest {
    Manifest,
    Event { event: CheckerEvent },
    Shutdown,
}

#[derive(Default, Serialize, Deserialize)]
struct WorkerResponse {
    ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest: Option<CheckerManifest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    findings: Vec<CheckerFinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

struct WorkerChecker {
    path: PathBuf,
    manifest: CheckerManifest,
    child: Child,
    stdin: BufWriter<ChildStdin>,
    responses: Receiver<String>,
}

impl WorkerChecker {
    fn spawn(path: &Path, timeout: Duration) -> Result<Self> {
        let executable = std::env::current_exe().context("failed to locate UniFlow executable")?;
        let mut child = Command::new(&executable)
            .arg("__checker-worker")
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .with_context(|| {
                format!(
                    "failed to start checker worker {} for {}",
                    executable.display(),
                    path.display()
                )
            })?;
        let stdin = child
            .stdin
            .take()
            .context("checker worker stdin unavailable")?;
        let stdout = child
            .stdout
            .take()
            .context("checker worker stdout unavailable")?;
        let (sender, responses) = mpsc::channel();
        thread::Builder::new()
            .name("uniflow-checker-worker-output".to_string())
            .spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines() {
                    match line {
                        Ok(line) if line.starts_with(IPC_PREFIX) => {
                            if sender.send(line[IPC_PREFIX.len()..].to_string()).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            })
            .context("failed to start checker worker reader")?;

        let mut worker = Self {
            path: path.to_path_buf(),
            manifest: CheckerManifest::new("pending", "pending", "0"),
            child,
            stdin: BufWriter::new(stdin),
            responses,
        };
        let response = worker.request(&WorkerRequest::Manifest, timeout)?;
        let manifest = response
            .manifest
            .ok_or_else(|| anyhow!("checker worker returned no manifest"))?;
        validate_manifest(&manifest, manifest.abi_version, path)?;
        worker.manifest = manifest;
        Ok(worker)
    }

    fn request(&mut self, request: &WorkerRequest, timeout: Duration) -> Result<WorkerResponse> {
        let text = serde_json::to_string(request).context("failed to serialize worker request")?;
        writeln!(self.stdin, "{IPC_PREFIX}{text}")
            .context("failed to write checker worker request")?;
        self.stdin
            .flush()
            .context("failed to flush checker worker request")?;

        let response_text = self.responses.recv_timeout(timeout).map_err(|error| {
            let _ = self.child.kill();
            let _ = self.child.wait();
            match error {
                mpsc::RecvTimeoutError::Timeout => anyhow!(
                    "checker {} exceeded the {:?} worker timeout",
                    self.path.display(),
                    timeout
                ),
                mpsc::RecvTimeoutError::Disconnected => anyhow!(
                    "checker worker for {} terminated without a response",
                    self.path.display()
                ),
            }
        })?;
        let response: WorkerResponse = serde_json::from_str(&response_text)
            .with_context(|| format!("invalid checker worker response: {response_text}"))?;
        if !response.ok {
            bail!(
                "checker worker for {} failed: {}",
                self.path.display(),
                response
                    .error
                    .unwrap_or_else(|| "unknown worker error".to_string())
            );
        }
        Ok(response)
    }

    fn handle_event(
        &mut self,
        event: &CheckerEvent,
        timeout: Duration,
    ) -> Result<Vec<CheckerFinding>> {
        let response = self.request(
            &WorkerRequest::Event {
                event: event.clone(),
            },
            timeout,
        )?;
        Ok(response.findings)
    }
}

impl Drop for WorkerChecker {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            if let Ok(text) = serde_json::to_string(&WorkerRequest::Shutdown) {
                let _ = writeln!(self.stdin, "{IPC_PREFIX}{text}");
                let _ = self.stdin.flush();
            }
            let deadline = Instant::now() + Duration::from_millis(100);
            while Instant::now() < deadline {
                if self.child.try_wait().ok().flatten().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(5));
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Entry point used by the hidden CLI worker mode.
pub fn run_worker(path: &Path) -> Result<()> {
    let mut checker = LoadedChecker::load(path).map_err(|error| format!("{error:#}"));
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = line.context("failed to read checker worker request")?;
        let Some(payload) = line.strip_prefix(IPC_PREFIX) else {
            continue;
        };
        let request: WorkerRequest = match serde_json::from_str(payload) {
            Ok(request) => request,
            Err(error) => {
                write_worker_response(
                    &mut writer,
                    &WorkerResponse {
                        ok: false,
                        error: Some(format!("invalid worker request: {error}")),
                        ..WorkerResponse::default()
                    },
                )?;
                continue;
            }
        };
        match request {
            WorkerRequest::Manifest => match &checker {
                Ok(checker) => write_worker_response(
                    &mut writer,
                    &WorkerResponse {
                        ok: true,
                        manifest: Some(checker.manifest.clone()),
                        ..WorkerResponse::default()
                    },
                )?,
                Err(error) => write_worker_response(
                    &mut writer,
                    &WorkerResponse {
                        ok: false,
                        error: Some(error.clone()),
                        ..WorkerResponse::default()
                    },
                )?,
            },
            WorkerRequest::Event { event } => match &mut checker {
                Ok(checker) => match checker.handle_event(&event) {
                    Ok(findings) => write_worker_response(
                        &mut writer,
                        &WorkerResponse {
                            ok: true,
                            findings,
                            ..WorkerResponse::default()
                        },
                    )?,
                    Err(error) => write_worker_response(
                        &mut writer,
                        &WorkerResponse {
                            ok: false,
                            error: Some(format!("{error:#}")),
                            ..WorkerResponse::default()
                        },
                    )?,
                },
                Err(error) => write_worker_response(
                    &mut writer,
                    &WorkerResponse {
                        ok: false,
                        error: Some(error.clone()),
                        ..WorkerResponse::default()
                    },
                )?,
            },
            WorkerRequest::Shutdown => {
                write_worker_response(
                    &mut writer,
                    &WorkerResponse {
                        ok: true,
                        ..WorkerResponse::default()
                    },
                )?;
                break;
            }
        }
    }
    Ok(())
}

fn write_worker_response(writer: &mut impl Write, response: &WorkerResponse) -> Result<()> {
    let text = serde_json::to_string(response).context("failed to serialize worker response")?;
    writeln!(writer, "{IPC_PREFIX}{text}").context("failed to write worker response")?;
    writer.flush().context("failed to flush worker response")
}

fn validate_manifest(manifest: &CheckerManifest, table_abi: u32, path: &Path) -> Result<()> {
    if manifest.abi_version != table_abi {
        bail!(
            "checker {} manifest declares ABI {}, table uses ABI {}",
            path.display(),
            manifest.abi_version,
            table_abi
        );
    }
    if !matches!(
        manifest.abi_version,
        CHECKER_ABI_VERSION_V1 | CHECKER_ABI_VERSION_V2
    ) {
        bail!(
            "checker {} uses unsupported ABI {}",
            path.display(),
            manifest.abi_version
        );
    }
    if manifest.id.trim().is_empty() {
        bail!("checker {} has an empty id", path.display());
    }
    if !manifest
        .id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        bail!(
            "checker id '{}' contains unsupported characters",
            manifest.id
        );
    }
    if manifest.name.trim().is_empty() {
        bail!("checker {} has an empty name", path.display());
    }
    if manifest.version.trim().is_empty() {
        bail!("checker {} has an empty version", path.display());
    }
    let mut kinds = HashSet::new();
    for kind in &manifest.event_kinds {
        if kind.trim().is_empty() {
            bail!("checker {} declares an empty event kind", manifest.id);
        }
        if !kinds.insert(kind) {
            bail!(
                "checker {} declares duplicate event kind '{}'",
                manifest.id,
                kind
            );
        }
        if !uniflow_checker_api::event_kind::is_known(kind) {
            bail!(
                "checker {} declares unknown event kind '{}'",
                manifest.id,
                kind
            );
        }
        if manifest.kind == CheckerKind::Frontend
            && !matches!(
                kind.as_str(),
                uniflow_checker_api::event_kind::ANALYSIS_START
                    | uniflow_checker_api::event_kind::SOURCE_FILE
                    | uniflow_checker_api::event_kind::HIR_PROGRAM
                    | uniflow_checker_api::event_kind::ANALYSIS_END
            )
        {
            bail!(
                "frontend checker {} cannot subscribe to dataflow event '{}'",
                manifest.id,
                kind
            );
        }
    }
    let mut rule_ids = HashSet::new();
    for rule in &manifest.rules {
        if rule.id.trim().is_empty() {
            bail!("checker {} declares an empty rule id", manifest.id);
        }
        if !rule
            .id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        {
            bail!(
                "checker {} rule id '{}' contains unsupported characters",
                manifest.id,
                rule.id
            );
        }
        if !rule_ids.insert(rule.id.as_str()) {
            bail!(
                "checker {} declares duplicate rule id '{}'",
                manifest.id,
                rule.id
            );
        }
        if rule.title.trim().is_empty() {
            bail!(
                "checker {} rule '{}' has an empty title",
                manifest.id,
                rule.id
            );
        }
        if !matches!(
            rule.default_level.as_str(),
            "error" | "warning" | "note" | "none"
        ) {
            bail!(
                "checker {} rule '{}' has unsupported default level '{}'",
                manifest.id,
                rule.id,
                rule.default_level
            );
        }
    }
    Ok(())
}

fn validate_finding(manifest: &CheckerManifest, finding: &CheckerFinding) -> Result<()> {
    if finding.rule_id.trim().is_empty() {
        bail!("finding has an empty rule id");
    }
    if finding.message.trim().is_empty() {
        bail!("finding {} has an empty message", finding.rule_id);
    }
    if !matches!(
        finding.level.as_str(),
        "error" | "warning" | "note" | "none"
    ) {
        bail!(
            "finding {} has unsupported level '{}'",
            finding.rule_id,
            finding.level
        );
    }
    if !manifest.rules.is_empty() {
        let qualified_finding = if finding.rule_id.starts_with(&format!("{}.", manifest.id)) {
            finding.rule_id.clone()
        } else {
            format!("{}.{}", manifest.id, finding.rule_id)
        };
        if !manifest.rules.iter().any(|rule| {
            let qualified_rule = if rule.id.starts_with(&format!("{}.", manifest.id)) {
                rule.id.clone()
            } else {
                format!("{}.{}", manifest.id, rule.id)
            };
            qualified_rule == qualified_finding
        }) {
            bail!(
                "checker {} emitted undeclared rule '{}'",
                manifest.id,
                finding.rule_id
            );
        }
    }
    validate_location(&finding.location, "primary")?;
    for location in &finding.related_locations {
        validate_location(location, "related")?;
    }
    for step in &finding.code_flow {
        validate_location(&step.location, "code-flow")?;
    }
    Ok(())
}

fn validate_location(location: &uniflow_checker_api::CheckerLocation, kind: &str) -> Result<()> {
    if location.uri.trim().is_empty() {
        bail!("{kind} finding location has an empty URI");
    }
    if location.line == 0 || location.column == 0 {
        bail!(
            "{kind} finding location {} uses zero-based line or column",
            location.uri
        );
    }
    Ok(())
}

fn normalize_finding(manifest: &CheckerManifest, finding: &mut CheckerFinding) {
    let local_rule = finding.rule_id.trim().trim_start_matches('.');
    finding.rule_id = if local_rule.starts_with(&format!("{}.", manifest.id)) {
        local_rule.to_string()
    } else {
        format!("{}.{}", manifest.id, local_rule)
    };
    finding
        .properties
        .insert("checkerId".to_string(), json!(manifest.id));
    finding
        .properties
        .insert("checkerName".to_string(), json!(manifest.name));
    finding
        .properties
        .insert("checkerVersion".to_string(), json!(manifest.version));
    finding
        .properties
        .insert("checkerAbi".to_string(), json!(manifest.abi_version));
    finding.properties.insert(
        "checkerKind".to_string(),
        json!(match manifest.kind {
            CheckerKind::Frontend => "frontend",
            CheckerKind::UnifiedDataflow => "unified_dataflow",
        }),
    );

    if finding
        .fingerprint
        .as_deref()
        .unwrap_or_default()
        .is_empty()
    {
        let mut digest = Sha256::new();
        for value in [
            manifest.id.as_str(),
            finding.rule_id.as_str(),
            finding.location.uri.as_str(),
            &finding.location.line.to_string(),
            &finding.location.column.to_string(),
            finding.message.as_str(),
        ] {
            digest.update(value.as_bytes());
            digest.update([0]);
        }
        finding.fingerprint = Some(format!("{:x}", digest.finalize()));
    }
}

unsafe fn take_plugin_string(
    value: *mut c_char,
    free_string: CheckerFreeStringFn,
) -> Result<String> {
    if value.is_null() {
        bail!("plugin returned a null string");
    }
    let text = unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned();
    unsafe { free_string(value) };
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uniflow_checker_api::CheckerLocation;

    fn manifest() -> CheckerManifest {
        CheckerManifest {
            abi_version: CHECKER_ABI_VERSION_V2,
            id: "test.checker".to_string(),
            name: "Test".to_string(),
            version: "1".to_string(),
            description: String::new(),
            kind: CheckerKind::UnifiedDataflow,
            event_kinds: Vec::new(),
            rules: Vec::new(),
        }
    }

    #[test]
    fn qualifies_rule_and_generates_fingerprint() {
        let manifest = manifest();
        let mut finding = CheckerFinding::new(
            "rule",
            "message",
            CheckerLocation {
                uri: "demo.c".to_string(),
                line: 4,
                column: 2,
                label: String::new(),
            },
        );
        validate_finding(&manifest, &finding).expect("valid");
        normalize_finding(&manifest, &mut finding);
        assert_eq!(finding.rule_id, "test.checker.rule");
        assert!(finding.fingerprint.is_some());
        assert_eq!(finding.properties["checkerId"], "test.checker");
        assert_eq!(finding.properties["checkerAbi"], CHECKER_ABI_VERSION_V2);
    }

    #[test]
    fn rejects_empty_rule_id() {
        let finding = CheckerFinding::new(
            "",
            "message",
            CheckerLocation {
                uri: "demo.c".to_string(),
                line: 1,
                column: 1,
                label: String::new(),
            },
        );
        assert!(validate_finding(&manifest(), &finding).is_err());
    }

    #[test]
    fn rejects_invalid_location() {
        let finding = CheckerFinding::new(
            "rule",
            "message",
            CheckerLocation {
                uri: String::new(),
                line: 0,
                column: 0,
                label: String::new(),
            },
        );
        assert!(validate_finding(&manifest(), &finding).is_err());
    }

    #[test]
    fn rejects_duplicate_manifest_events() {
        let mut manifest = manifest();
        manifest.event_kinds = vec!["call".to_string(), "call".to_string()];
        assert!(validate_manifest(&manifest, CHECKER_ABI_VERSION_V2, Path::new("test")).is_err());
    }

    #[test]
    fn validates_declared_rules_and_rejects_undeclared_findings() {
        let mut manifest = manifest();
        manifest.rules = vec![uniflow_checker_api::CheckerRule::new(
            "declared",
            "Declared rule",
        )];
        validate_manifest(&manifest, CHECKER_ABI_VERSION_V2, Path::new("test"))
            .expect("declared rule metadata should be valid");
        let location = CheckerLocation {
            uri: "demo.c".to_string(),
            line: 1,
            column: 1,
            label: String::new(),
        };
        let declared = CheckerFinding::new("declared", "message", location.clone());
        validate_finding(&manifest, &declared).expect("declared finding");
        let qualified = CheckerFinding::new("test.checker.declared", "message", location.clone());
        validate_finding(&manifest, &qualified).expect("qualified declared finding");
        let unknown = CheckerFinding::new("unknown", "message", location);
        assert!(validate_finding(&manifest, &unknown).is_err());

        manifest.rules = vec![uniflow_checker_api::CheckerRule::new(
            "test.checker.qualified",
            "Qualified rule",
        )];
        let local = CheckerFinding::new(
            "qualified",
            "message",
            CheckerLocation {
                uri: "demo.c".to_string(),
                line: 1,
                column: 1,
                label: String::new(),
            },
        );
        validate_finding(&manifest, &local).expect("local finding for qualified declaration");

        manifest.rules = vec![
            uniflow_checker_api::CheckerRule::new("declared", "Declared"),
            uniflow_checker_api::CheckerRule::new("declared", "Duplicate"),
        ];
        assert!(validate_manifest(&manifest, CHECKER_ABI_VERSION_V2, Path::new("test")).is_err());
    }

    #[test]
    fn rejects_unknown_manifest_event() {
        let mut manifest = manifest();
        manifest.event_kinds = vec!["flow_summry".to_string()];
        assert!(validate_manifest(&manifest, CHECKER_ABI_VERSION_V2, Path::new("test")).is_err());
    }

    #[test]
    fn frontend_manifest_rejects_dataflow_events() {
        let mut manifest = manifest();
        manifest.kind = CheckerKind::Frontend;
        manifest.event_kinds = vec![uniflow_checker_api::event_kind::IR_PROGRAM.to_string()];
        assert!(validate_manifest(&manifest, CHECKER_ABI_VERSION_V2, Path::new("test")).is_err());
        manifest.event_kinds = vec![uniflow_checker_api::event_kind::HIR_PROGRAM.to_string()];
        assert!(validate_manifest(&manifest, CHECKER_ABI_VERSION_V2, Path::new("test")).is_ok());
    }

    #[test]
    fn worker_protocol_round_trips() {
        let request = WorkerRequest::Event {
            event: CheckerEvent {
                kind: "call".to_string(),
                sequence: 7,
                payload: json!({"callee": "strcpy"}),
            },
        };
        let text = serde_json::to_string(&request).expect("serialize");
        let decoded: WorkerRequest = serde_json::from_str(&text).expect("decode");
        assert!(matches!(decoded, WorkerRequest::Event { .. }));
    }
}
