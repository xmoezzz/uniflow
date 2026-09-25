//! A minimal, pure-Rust OCI Distribution API v2 client — enough to resolve
//! an image reference (`registry/repo:tag`) to its manifest, follow a
//! multi-platform manifest list/index down to one real image, and pull
//! every blob (config + layers) into an on-disk OCI image-layout
//! directory that `uniflow-container-image::squash_image` already knows
//! how to read. No `docker`/`skopeo`/`crane` binary is ever shelled out to.
//!
//! Every blob is verified against its own claimed digest as it's
//! downloaded — unlike `container_image`'s local-tarball path (which
//! trusts an already-on-disk file the caller chose), this is the actual
//! untrusted-network-fetch boundary, so integrity checking belongs here.
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

const ACCEPT_MANIFEST_TYPES: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.list.v2+json";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    /// Either a tag (`"latest"`) or a full `sha256:...` digest.
    pub reference: String,
}

/// Parses a Docker-style image reference. Bare names (`"alpine"`) and
/// unqualified paths (`"bitnami/nginx"`) resolve to Docker Hub
/// (`registry-1.docker.io` — the real API host; `docker.io` itself does
/// not serve `/v2/`), with an implicit `library/` prefix for single-segment
/// names, matching what `docker pull` itself does.
pub fn parse_reference(image: &str) -> ImageReference {
    let (name_part, reference) = match image.rsplit_once('@') {
        Some((name, digest)) => (name, digest.to_string()),
        None => {
            let last_slash = image.rfind('/');
            let search_from = last_slash.map(|i| i + 1).unwrap_or(0);
            match image[search_from..].rfind(':') {
                Some(rel_colon) => (&image[..search_from + rel_colon], image[search_from + rel_colon + 1..].to_string()),
                None => (image, "latest".to_string()),
            }
        }
    };

    let first_slash = name_part.find('/');
    let looks_like_host = |segment: &str| segment.contains('.') || segment.contains(':') || segment == "localhost";
    match first_slash {
        Some(idx) if looks_like_host(&name_part[..idx]) => {
            ImageReference { registry: name_part[..idx].to_string(), repository: name_part[idx + 1..].to_string(), reference }
        }
        Some(_) => ImageReference { registry: "registry-1.docker.io".to_string(), repository: name_part.to_string(), reference },
        None => ImageReference {
            registry: "registry-1.docker.io".to_string(),
            repository: format!("library/{name_part}"),
            reference,
        },
    }
}

pub struct RegistryAuth {
    pub username: String,
    pub password: String,
}

/// Pulls `image` and writes a complete OCI image-layout directory (ready
/// for `uniflow_container_image::squash_image`) under a fresh temp dir,
/// which the caller owns and must keep alive as long as it's needed.
///
/// `insecure_http` talks plain HTTP instead of HTTPS — real support for
/// on-prem/air-gapped internal registries that run without TLS (the same
/// use case `docker`'s own `--insecure-registry` covers), not just a test
/// convenience, though it doubles as exactly that: it's what lets this
/// crate's own tests run against a local mock registry with no TLS setup.
pub fn pull_image(image: &str, auth: Option<&RegistryAuth>, platform: (&str, &str), insecure_http: bool) -> Result<tempfile::TempDir> {
    let reference = parse_reference(image);
    let client = reqwest::blocking::Client::builder().build().context("failed to build HTTP client")?;
    let scheme = if insecure_http { "http" } else { "https" };
    let base = format!("{scheme}://{}/v2", reference.registry);

    // One token, obtained on whichever request first gets challenged, reused
    // for the rest of this pull — a registry's token scope covers the whole
    // repository, not one specific request, so re-doing the challenge round
    // trip for every single blob (as a per-call-only cache would) is pure
    // waste on top of what's already a network-bound operation.
    let mut token: Option<String> = None;

    let (manifest_bytes, manifest_digest) =
        fetch_manifest(&client, &base, &reference.repository, &reference.reference, auth, platform, &mut token)?;
    let manifest: OciManifest = serde_json::from_slice(&manifest_bytes).context("failed to parse image manifest")?;

    let layout = tempfile::Builder::new().prefix("uniflow-oci-pull-").tempdir().context("failed to create layout scratch dir")?;
    let blobs_dir = layout.path().join("blobs/sha256");
    fs::create_dir_all(&blobs_dir).context("failed to create blobs directory")?;
    fs::write(layout.path().join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).context("failed to write oci-layout")?;

    write_verified_blob(&blobs_dir, &manifest_digest, &manifest_bytes)?;
    fetch_blob(&client, &base, &reference.repository, &manifest.config.digest, auth, &blobs_dir, &mut token)?;
    for layer in &manifest.layers {
        fetch_blob(&client, &base, &reference.repository, &layer.digest, auth, &blobs_dir, &mut token)?;
    }

    let index = serde_json::json!({
        "schemaVersion": 2,
        "manifests": [{ "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest_digest, "size": manifest_bytes.len() }],
    });
    fs::write(layout.path().join("index.json"), serde_json::to_vec(&index)?).context("failed to write index.json")?;

    Ok(layout)
}

#[derive(Deserialize)]
struct OciDescriptor {
    digest: String,
    #[serde(rename = "mediaType", default)]
    #[allow(dead_code)]
    media_type: String,
    platform: Option<OciPlatform>,
}

#[derive(Deserialize)]
struct OciPlatform {
    architecture: String,
    os: String,
}

#[derive(Deserialize)]
struct OciManifest {
    config: OciDescriptor,
    layers: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
struct ManifestList {
    manifests: Vec<OciDescriptor>,
}

/// Resolves `reference` (a tag or digest) to a real single-image manifest's
/// raw bytes and its own digest — following one level of manifest-list/
/// index indirection if the registry returns a multi-platform list,
/// picking the first entry matching `platform` (falling back to the
/// list's first entry if nothing matches exactly, rather than failing a
/// pull outright over an unlisted architecture).
fn fetch_manifest(
    client: &reqwest::blocking::Client,
    base: &str,
    repository: &str,
    reference: &str,
    auth: Option<&RegistryAuth>,
    platform: (&str, &str),
    token: &mut Option<String>,
) -> Result<(Vec<u8>, String)> {
    let url = format!("{base}/{repository}/manifests/{reference}");
    let bytes = authenticated_get(client, &url, repository, "pull", auth, ACCEPT_MANIFEST_TYPES, token)?;
    let digest = format!("sha256:{}", hex_sha256(&bytes));

    if let Ok(list) = serde_json::from_slice::<ManifestList>(&bytes) {
        if !list.manifests.is_empty() {
            let chosen = list
                .manifests
                .iter()
                .find(|m| m.platform.as_ref().is_some_and(|p| p.architecture == platform.0 && p.os == platform.1))
                .or_else(|| list.manifests.first())
                .context("manifest list has no entries")?;
            return fetch_manifest(client, base, repository, &chosen.digest, auth, platform, token);
        }
    }
    Ok((bytes, digest))
}

fn fetch_blob(
    client: &reqwest::blocking::Client,
    base: &str,
    repository: &str,
    digest: &str,
    auth: Option<&RegistryAuth>,
    blobs_dir: &Path,
    token: &mut Option<String>,
) -> Result<()> {
    let url = format!("{base}/{repository}/blobs/{digest}");
    let bytes = authenticated_get(client, &url, repository, "pull", auth, "*/*", token)?;
    write_verified_blob(blobs_dir, digest, &bytes)
}

fn write_verified_blob(blobs_dir: &Path, digest: &str, bytes: &[u8]) -> Result<()> {
    let (alg, hex) = digest.split_once(':').with_context(|| format!("malformed digest {digest:?}"))?;
    if alg != "sha256" {
        bail!("unsupported digest algorithm {alg:?} (only sha256 is supported)");
    }
    let actual = hex_sha256(bytes);
    if actual != hex {
        bail!("blob {digest} failed integrity verification (got sha256:{actual})");
    }
    fs::write(blobs_dir.join(hex), bytes).with_context(|| format!("failed to write blob {digest}"))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// One GET, using a cached bearer token if `token` already holds one from
/// an earlier call in this same pull, and otherwise (or if that cached
/// token turns out to be stale/rejected) obtaining a fresh one via the
/// registry's `401 WWW-Authenticate: Bearer realm=...,service=...,scope=...`
/// challenge (Docker Hub's standard flow for both anonymous and
/// authenticated pulls — even anonymous pulls need a short-lived anonymous
/// token). `auth` supplies HTTP Basic credentials to the token endpoint
/// for private images; anonymous pulls of public images pass `None`.
fn authenticated_get(
    client: &reqwest::blocking::Client,
    url: &str,
    repository: &str,
    action: &str,
    auth: Option<&RegistryAuth>,
    accept: &str,
    token: &mut Option<String>,
) -> Result<Vec<u8>> {
    let send = |bearer: Option<&str>| {
        let mut req = client.get(url).header("Accept", accept);
        if let Some(token) = bearer {
            req = req.bearer_auth(token);
        } else if let Some(creds) = auth {
            req = req.basic_auth(&creds.username, Some(&creds.password));
        }
        req.send()
    };

    if let Some(cached) = token.clone() {
        let response = send(Some(&cached)).with_context(|| format!("request to {url} failed"))?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            let bytes = response.error_for_status().context("registry rejected cached-token request")?.bytes().context("failed to read response body")?;
            return Ok(bytes.to_vec());
        }
        // Cached token rejected (expired, or scoped to a different
        // repository/action) — fall through and re-challenge below.
    }

    let response = send(None).with_context(|| format!("request to {url} failed"))?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        let challenge = response
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .context("registry returned 401 with no WWW-Authenticate challenge")?
            .to_string();
        let fresh_token = fetch_bearer_token(client, &challenge, repository, action, auth)?;
        let response = send(Some(&fresh_token)).with_context(|| format!("authenticated request to {url} failed"))?;
        let bytes = response.error_for_status().context("registry rejected authenticated request")?.bytes().context("failed to read response body")?;
        *token = Some(fresh_token);
        return Ok(bytes.to_vec());
    }
    let bytes = response.error_for_status().context("registry request failed")?.bytes().context("failed to read response body")?;
    Ok(bytes.to_vec())
}

fn fetch_bearer_token(
    client: &reqwest::blocking::Client,
    challenge: &str,
    repository: &str,
    action: &str,
    auth: Option<&RegistryAuth>,
) -> Result<String> {
    let params = challenge.trim_start_matches("Bearer ").split(',').filter_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        Some((k.trim().to_string(), v.trim().trim_matches('"').to_string()))
    });
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for (k, v) in params {
        match k.as_str() {
            "realm" => realm = Some(v),
            "service" => service = Some(v),
            "scope" => scope = Some(v),
            _ => {}
        }
    }
    let realm = realm.context("auth challenge had no realm")?;
    let mut request = client.get(&realm);
    if let Some(service) = &service {
        request = request.query(&[("service", service)]);
    }
    let scope = scope.unwrap_or_else(|| format!("repository:{repository}:{action}"));
    request = request.query(&[("scope", scope)]);
    if let Some(creds) = auth {
        request = request.basic_auth(&creds.username, Some(&creds.password));
    }
    let response: TokenResponse = request.send().context("token request failed")?.error_for_status().context("token request rejected")?.json().context("failed to parse token response")?;
    response.token.or(response.access_token).context("token response had neither `token` nor `access_token`")
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bare_name_as_a_docker_hub_library_image() {
        let r = parse_reference("alpine");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn parses_a_tagged_unqualified_org_path_as_docker_hub() {
        let r = parse_reference("bitnami/nginx:1.25");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "bitnami/nginx");
        assert_eq!(r.reference, "1.25");
    }

    #[test]
    fn parses_a_private_registry_with_a_port_without_confusing_it_for_a_tag() {
        let r = parse_reference("registry.example.com:5000/team/app:v2");
        assert_eq!(r.registry, "registry.example.com:5000");
        assert_eq!(r.repository, "team/app");
        assert_eq!(r.reference, "v2");
    }

    #[test]
    fn parses_a_digest_reference() {
        let r = parse_reference("myregistry.io/app@sha256:abcdef1234");
        assert_eq!(r.registry, "myregistry.io");
        assert_eq!(r.repository, "app");
        assert_eq!(r.reference, "sha256:abcdef1234");
    }

    #[test]
    fn rejects_a_blob_that_fails_integrity_verification() {
        let dir = tempfile::tempdir().unwrap();
        let err = write_verified_blob(dir.path(), "sha256:0000000000000000000000000000000000000000000000000000000000000000", b"hello").unwrap_err();
        assert!(err.to_string().contains("failed integrity verification"));
    }

    #[test]
    fn accepts_a_blob_whose_hash_matches_its_claimed_digest() {
        let dir = tempfile::tempdir().unwrap();
        let real_digest = format!("sha256:{}", hex_sha256(b"hello"));
        write_verified_blob(dir.path(), &real_digest, b"hello").unwrap();
        assert_eq!(fs::read(dir.path().join(hex_sha256(b"hello"))).unwrap(), b"hello");
    }

    /// A minimal fake registry: serves an unauthenticated manifest/blob GET
    /// straight away, no challenge — the common case for an already-public,
    /// no-auth-required internal registry.
    struct MockRegistry {
        server: std::sync::Arc<tiny_http::Server>,
        port: u16,
    }

    impl MockRegistry {
        fn start() -> Self {
            let server = tiny_http::Server::http("127.0.0.1:0").expect("start mock registry");
            let port = server.server_addr().to_ip().expect("ip addr").port();
            Self { server: std::sync::Arc::new(server), port }
        }

        fn base_image_ref(&self, repo: &str, tag: &str) -> String {
            format!("127.0.0.1:{}/{repo}:{tag}", self.port)
        }
    }

    fn manifest_json(config_digest: &str, config_size: usize, layer_digest: &str, layer_size: usize) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest, "size": config_size },
            "layers": [{ "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer_digest, "size": layer_size }],
        }))
        .unwrap()
    }

    #[test]
    fn pulls_a_real_image_end_to_end_with_no_auth_challenge() {
        let registry = MockRegistry::start();
        let config_bytes = b"{\"config\":true}".to_vec();
        let layer_bytes = b"a fake tar layer".to_vec();
        let config_digest = format!("sha256:{}", hex_sha256(&config_bytes));
        let layer_digest = format!("sha256:{}", hex_sha256(&layer_bytes));
        let manifest_bytes = manifest_json(&config_digest, config_bytes.len(), &layer_digest, layer_bytes.len());
        let manifest_digest = format!("sha256:{}", hex_sha256(&manifest_bytes));

        let server = registry.server.clone();
        let thread_manifest = manifest_bytes.clone();
        let thread_config = config_bytes.clone();
        let thread_layer = layer_bytes.clone();
        let thread_config_digest = config_digest.clone();
        let handle = std::thread::spawn(move || {
            for _ in 0..3 {
                let request = server.recv().unwrap();
                let url = request.url().to_string();
                if url.contains("/manifests/") {
                    request.respond(tiny_http::Response::from_data(thread_manifest.clone())).unwrap();
                } else if url.ends_with(&thread_config_digest) {
                    request.respond(tiny_http::Response::from_data(thread_config.clone())).unwrap();
                } else {
                    request.respond(tiny_http::Response::from_data(thread_layer.clone())).unwrap();
                }
            }
        });

        let image = registry.base_image_ref("myrepo", "latest");
        let layout = pull_image(&image, None, ("amd64", "linux"), true).expect("pull_image should succeed");
        handle.join().unwrap();

        assert_eq!(fs::read(layout.path().join("blobs/sha256").join(manifest_digest.trim_start_matches("sha256:"))).unwrap(), manifest_bytes);
        assert_eq!(fs::read(layout.path().join("blobs/sha256").join(config_digest.trim_start_matches("sha256:"))).unwrap(), config_bytes);
        assert_eq!(fs::read(layout.path().join("blobs/sha256").join(layer_digest.trim_start_matches("sha256:"))).unwrap(), layer_bytes);
        assert!(layout.path().join("oci-layout").exists());
        assert!(layout.path().join("index.json").exists());
    }

    #[test]
    fn pulls_through_a_bearer_token_challenge() {
        let registry = MockRegistry::start();
        let manifest_bytes = manifest_json("sha256:0000000000000000000000000000000000000000000000000000000000000000", 0, "sha256:1111111111111111111111111111111111111111111111111111111111111111", 0);
        // Both blobs are zero-length placeholders here — this test's only
        // concern is the auth handshake, not blob content, so it stops
        // after the manifest is fetched successfully.
        let realm = format!("http://127.0.0.1:{}/token", registry.port);

        let server = registry.server.clone();
        let manifest_for_thread = manifest_bytes.clone();
        let handle = std::thread::spawn(move || {
            // First request: no Authorization header -> 401 challenge.
            let request = server.recv().unwrap();
            assert!(request.headers().iter().all(|h| h.field.as_str().as_str().to_lowercase() != "authorization"));
            let header = tiny_http::Header::from_bytes(
                &b"WWW-Authenticate"[..],
                format!("Bearer realm=\"{realm}\",service=\"test-registry\",scope=\"repository:myrepo:pull\"").as_bytes(),
            )
            .unwrap();
            request.respond(tiny_http::Response::from_data(Vec::new()).with_status_code(401).with_header(header)).unwrap();

            // Second request: the token endpoint.
            let token_request = server.recv().unwrap();
            assert!(token_request.url().starts_with("/token"));
            token_request.respond(tiny_http::Response::from_data(br#"{"token":"secret-token"}"#.to_vec())).unwrap();

            // Third request: retried with the bearer token this time.
            let authed_request = server.recv().unwrap();
            let has_bearer = authed_request.headers().iter().any(|h| {
                h.field.as_str().as_str().to_lowercase() == "authorization" && h.value.as_str().starts_with("Bearer secret-token")
            });
            assert!(has_bearer, "retry must carry the token obtained from the challenge");
            authed_request.respond(tiny_http::Response::from_data(manifest_for_thread)).unwrap();
        });

        let mut token = None;
        let base = format!("http://127.0.0.1:{}/v2", registry.port);
        let (fetched, _digest) = fetch_manifest(
            &reqwest::blocking::Client::new(),
            &base,
            "myrepo",
            "latest",
            None,
            ("amd64", "linux"),
            &mut token,
        )
        .expect("fetch_manifest should follow the challenge and succeed");
        handle.join().unwrap();

        assert_eq!(fetched, manifest_bytes);
        assert_eq!(token.as_deref(), Some("secret-token"), "the token must be cached for reuse by later blob fetches");
    }
}
