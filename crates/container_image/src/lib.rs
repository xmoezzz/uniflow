//! Squashes a container image — a `docker save`-format tarball, or an
//! already-extracted OCI image-layout directory — into one filesystem tree
//! ready for SCA/SAST/OS-package scanning, applying layers in the image's
//! real order and honoring OCI whiteout markers.
//!
//! `uniflow-archive-extract`'s recursive extractor deliberately has no
//! concept of "later archive wins" or "a `.wh.foo` entry means delete
//! `foo`" — it just finds and extracts every archive it sees into one flat
//! scratch directory. This crate calls it once per layer, strictly in the
//! order the image's manifest declares, and merges each layer's output
//! into a shared destination itself, which is where whiteout semantics are
//! actually applied.
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use uniflow_archive_extract::{extract_archives_recursively, ExtractOptions};
use walkdir::WalkDir;

const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";
const WHITEOUT_PREFIX: &str = ".wh.";

#[derive(Debug, Default)]
pub struct SquashReport {
    pub layer_count: usize,
    pub files_written: u64,
    pub whiteouts_applied: u64,
}

pub struct SquashedImage {
    pub root: tempfile::TempDir,
    pub report: SquashReport,
}

/// `source` is either a `docker save`-format tarball (a single file) or an
/// already-extracted OCI image-layout directory (containing `index.json`/
/// `oci-layout`) — e.g. what `skopeo copy --format oci docker://... dir:...`
/// produces, or what this crate's own caller gets after unpacking one.
pub fn squash_image(source: &Path, options: &ExtractOptions) -> Result<SquashedImage> {
    if source.is_dir() {
        return squash_from_layout_dir(source, options);
    }
    squash_docker_save_tarball(source, options)
}

#[derive(Deserialize)]
struct LegacyManifestEntry {
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

#[derive(Deserialize)]
struct OciIndex {
    manifests: Vec<OciDescriptor>,
}

#[derive(Deserialize)]
struct OciDescriptor {
    digest: String,
}

#[derive(Deserialize)]
struct OciManifest {
    layers: Vec<OciDescriptor>,
}

/// `extract_archives_recursively` puts each archive's content in its own
/// `NNNNNN_<stem>` subdirectory of the scratch dir it returns (see its
/// `entry_dir` naming in `uniflow-archive-extract::lib`), never flat at
/// the scratch root — every call site here extracts exactly one archive at
/// a time, so there's always exactly one such subdirectory to resolve.
fn first_extracted_subdir(scratch_root: &Path) -> Result<PathBuf> {
    // `read_dir` order is arbitrary; the archive that was asked for is the
    // lowest-numbered `NNNNNN_` entry, so pick that one deterministically
    // rather than whichever directory the filesystem happens to list first.
    let mut dirs: Vec<PathBuf> = fs::read_dir(scratch_root)
        .with_context(|| format!("failed to read {}", scratch_root.display()))?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort();
    dirs.into_iter().next().with_context(|| format!("{} contains no extracted archive directory", scratch_root.display()))
}

/// Resolves a `sha256:<hex>`-style OCI digest to its blob file path. This
/// does NOT verify the blob's actual hash matches the claimed digest —
/// this crate squashes an image for content scanning, not for running it,
/// so a corrupted/tampered blob just produces a scan of wrong content
/// rather than a security guarantee being silently skipped. Verifying
/// integrity would be a reasonable follow-up for anyone pulling images
/// from an untrusted registry rather than scanning a locally-built one.
fn digest_to_blob_path(root: &Path, digest: &str) -> Result<PathBuf> {
    let (alg, hex) = digest.split_once(':').with_context(|| format!("malformed digest {digest:?}"))?;
    Ok(root.join("blobs").join(alg).join(hex))
}

/// A `docker save` tarball's outer layer is itself just a tar — extracted
/// with a hardcoded `max_depth: 1` (regardless of what the caller passed)
/// so we get exactly `manifest.json`/`index.json` plus the raw, still-
/// packed per-layer blobs, without the generic recursive extractor also
/// unpacking those blobs itself (which would lose layer ordering and
/// whiteout awareness). Each layer is then extracted separately, in order,
/// using the caller's real `options`.
fn squash_docker_save_tarball(tarball: &Path, options: &ExtractOptions) -> Result<SquashedImage> {
    let outer_options = ExtractOptions { max_depth: 1, ..options.clone() };
    let Some((outer, _)) = extract_archives_recursively(&[tarball.to_path_buf()], &outer_options)
        .context("failed to extract the outer image tarball")?
    else {
        bail!("{} does not look like an archive at all", tarball.display());
    };
    let layout_root = first_extracted_subdir(outer.path())?;
    squash_from_layout_dir(&layout_root, options)
}

/// `layout_root` already contains either a legacy `manifest.json` (what
/// `docker save` always includes, even on modern Docker, for backward
/// compatibility) or an OCI `index.json` — checked in that order, since a
/// modern `docker save` tarball's root actually satisfies both and the
/// legacy path is simpler to resolve.
fn squash_from_layout_dir(layout_root: &Path, options: &ExtractOptions) -> Result<SquashedImage> {
    let layer_paths = if layout_root.join("manifest.json").exists() {
        resolve_legacy_layers(layout_root)?
    } else if layout_root.join("index.json").exists() {
        resolve_oci_layers(layout_root)?
    } else {
        bail!("{} contains neither manifest.json nor index.json — not a recognized image layout", layout_root.display());
    };

    let squashed = tempfile::Builder::new().prefix("uniflow-image-squash-").tempdir().context("failed to create squash scratch dir")?;
    let mut report = SquashReport { layer_count: layer_paths.len(), ..Default::default() };

    // A layer is unpacked exactly one level deep. Recursing would also
    // unpack every `.gz` inside it (`changelog.Debian.gz`, man pages, …)
    // into sibling scratch directories — and a real image's rootfs would
    // then compete with those for "the" extracted directory. Nested
    // archives in the squashed tree are the SCA scan's job, afterwards.
    let layer_options = ExtractOptions { max_depth: 1, ..options.clone() };
    for layer_path in &layer_paths {
        let Some((layer_extracted, _)) = extract_archives_recursively(std::slice::from_ref(layer_path), &layer_options)
            .with_context(|| format!("failed to extract layer {}", layer_path.display()))?
        else {
            bail!("layer {} does not look like an archive", layer_path.display());
        };
        let layer_root = first_extracted_subdir(layer_extracted.path())?;
        merge_layer(&layer_root, squashed.path(), &mut report)?;
    }

    Ok(SquashedImage { root: squashed, report })
}

fn resolve_legacy_layers(layout_root: &Path) -> Result<Vec<PathBuf>> {
    let text = fs::read_to_string(layout_root.join("manifest.json")).context("failed to read manifest.json")?;
    let entries: Vec<LegacyManifestEntry> = serde_json::from_str(&text).context("failed to parse manifest.json")?;
    let entry = entries.first().context("manifest.json has no image entries")?;
    Ok(entry.layers.iter().map(|rel| layout_root.join(rel)).collect())
}

fn resolve_oci_layers(layout_root: &Path) -> Result<Vec<PathBuf>> {
    let index_text = fs::read_to_string(layout_root.join("index.json")).context("failed to read index.json")?;
    let index: OciIndex = serde_json::from_str(&index_text).context("failed to parse index.json")?;
    let top = index.manifests.first().context("index.json lists no manifests")?;
    let manifest_blob = digest_to_blob_path(layout_root, &top.digest)?;
    let manifest_text = fs::read_to_string(&manifest_blob)
        .with_context(|| format!("failed to read image manifest blob {}", manifest_blob.display()))?;
    let manifest: OciManifest = serde_json::from_str(&manifest_text).context("failed to parse image manifest blob")?;
    manifest.layers.iter().map(|layer| digest_to_blob_path(layout_root, &layer.digest)).collect()
}

/// Merges one already-extracted layer's tree into `dest`, in two passes so
/// processing order within the layer never matters: first apply every
/// whiteout in this layer (deleting/clearing paths in `dest` that came
/// from earlier, lower layers), then copy across every real file this
/// layer contains. A `.wh..wh..opq` marker clears every pre-existing
/// entry in its own directory (an "opaque" whiteout — this directory is
/// fully replaced by this layer, not merged with lower layers); a plain
/// `.wh.<name>` marker deletes just that one sibling.
fn merge_layer(layer_root: &Path, dest: &Path, report: &mut SquashReport) -> Result<()> {
    let mut to_delete: Vec<PathBuf> = Vec::new();
    let mut to_clear_dirs: Vec<PathBuf> = Vec::new();
    let mut to_copy: Vec<PathBuf> = Vec::new();

    for entry in WalkDir::new(layer_root).into_iter().filter_map(|e| e.ok()) {
        let rel = entry.path().strip_prefix(layer_root).unwrap_or(entry.path());
        if rel.as_os_str().is_empty() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy();
        if file_name == OPAQUE_WHITEOUT {
            let dir_rel = rel.parent().unwrap_or(Path::new(""));
            to_clear_dirs.push(dest.join(dir_rel));
        } else if let Some(target_name) = file_name.strip_prefix(WHITEOUT_PREFIX) {
            let target_rel = rel.with_file_name(target_name);
            to_delete.push(dest.join(target_rel));
        } else if entry.file_type().is_file() {
            to_copy.push(rel.to_path_buf());
        }
    }

    for dir in to_clear_dirs {
        if dir.is_dir() {
            for child in fs::read_dir(&dir).with_context(|| format!("failed to read {}", dir.display()))? {
                let child = child?.path();
                if child.is_dir() {
                    fs::remove_dir_all(&child).ok();
                } else {
                    fs::remove_file(&child).ok();
                }
            }
        }
        report.whiteouts_applied += 1;
    }
    for path in to_delete {
        if path.is_dir() {
            fs::remove_dir_all(&path).ok();
        } else {
            fs::remove_file(&path).ok();
        }
        report.whiteouts_applied += 1;
    }
    for rel in to_copy {
        let from = layer_root.join(&rel);
        let to = dest.join(&rel);
        if let Some(parent) = to.parent() {
            fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::copy(&from, &to).with_context(|| format!("failed to copy {} to {}", from.display(), to.display()))?;
        report.files_written += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_tar(path: &Path, files: &[(&str, &[u8])]) {
        let file = fs::File::create(path).unwrap();
        let mut builder = tar::Builder::new(file);
        for (name, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, name, *contents).unwrap();
        }
        builder.finish().unwrap();
    }

    #[test]
    fn squashes_legacy_docker_save_layers_in_manifest_order_with_later_layer_winning() {
        let dir = tempfile::tempdir().unwrap();

        write_tar(&dir.path().join("layer1.tar"), &[("etc/os-release", b"layer1"), ("app/old.txt", b"from layer1")]);
        write_tar(&dir.path().join("layer2.tar"), &[("etc/os-release", b"layer2 wins")]);

        let outer = dir.path().join("image.tar");
        write_tar(
            &outer,
            &[
                ("manifest.json", br#"[{"Config":"cfg.json","Layers":["layer1.tar","layer2.tar"]}]"#),
                ("layer1.tar", &fs::read(dir.path().join("layer1.tar")).unwrap()),
                ("layer2.tar", &fs::read(dir.path().join("layer2.tar")).unwrap()),
            ],
        );

        let squashed = squash_image(&outer, &ExtractOptions::default()).unwrap();
        assert_eq!(squashed.report.layer_count, 2);
        let os_release = fs::read_to_string(squashed.root.path().join("etc/os-release")).unwrap();
        assert_eq!(os_release, "layer2 wins", "a later layer must overwrite an earlier layer's same-path file");
        assert!(squashed.root.path().join("app/old.txt").exists(), "files with no later override must survive");
    }

    #[test]
    fn a_layer_with_nested_compressed_files_keeps_its_whole_rootfs() {
        // Real layers are full of `.gz` files (Debian changelogs, man
        // pages). Recursively unpacking them used to put each one in a
        // sibling scratch dir, and the squash then picked one of *those* as
        // "the layer" — debian:12 squashed to a single changelog file.
        let dir = tempfile::tempdir().unwrap();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, b"changelog text").unwrap();
        let gz = gz.finish().unwrap();
        write_tar(
            &dir.path().join("layer.tar"),
            &[
                ("usr/share/doc/a/changelog.Debian.gz", &gz),
                ("usr/share/doc/b/changelog.Debian.gz", &gz),
                ("usr/lib/os-release", b"ID=debian\nVERSION_ID=\"12\"\n"),
                ("var/lib/dpkg/status", b"Package: bash\nStatus: install ok installed\nVersion: 5.2\n\n"),
            ],
        );
        let outer = dir.path().join("image.tar");
        write_tar(
            &outer,
            &[
                ("manifest.json", br#"[{"Config":"cfg.json","Layers":["layer.tar"]}]"#),
                ("layer.tar", &fs::read(dir.path().join("layer.tar")).unwrap()),
            ],
        );
        let squashed = squash_image(&outer, &ExtractOptions::default()).unwrap();
        let root = squashed.root.path();
        assert!(root.join("usr/lib/os-release").exists());
        assert!(root.join("var/lib/dpkg/status").exists());
        assert!(root.join("usr/share/doc/a/changelog.Debian.gz").exists(), "nested archives stay packed in the rootfs");
        assert_eq!(squashed.report.files_written, 4);
    }

    #[test]
    fn a_whiteout_marker_deletes_the_earlier_layers_file() {
        let dir = tempfile::tempdir().unwrap();
        write_tar(&dir.path().join("layer1.tar"), &[("app/secret.txt", b"leaked")]);
        write_tar(&dir.path().join("layer2.tar"), &[("app/.wh.secret.txt", b"")]);

        let outer = dir.path().join("image.tar");
        write_tar(
            &outer,
            &[
                ("manifest.json", br#"[{"Config":"cfg.json","Layers":["layer1.tar","layer2.tar"]}]"#),
                ("layer1.tar", &fs::read(dir.path().join("layer1.tar")).unwrap()),
                ("layer2.tar", &fs::read(dir.path().join("layer2.tar")).unwrap()),
            ],
        );

        let squashed = squash_image(&outer, &ExtractOptions::default()).unwrap();
        assert!(!squashed.root.path().join("app/secret.txt").exists(), "a whiteout must delete the earlier layer's file");
        assert!(squashed.report.whiteouts_applied >= 1);
    }

    #[test]
    fn an_opaque_whiteout_clears_every_earlier_entry_in_that_directory() {
        let dir = tempfile::tempdir().unwrap();
        write_tar(&dir.path().join("layer1.tar"), &[("app/one.txt", b"a"), ("app/two.txt", b"b")]);
        write_tar(&dir.path().join("layer2.tar"), &[("app/.wh..wh..opq", b""), ("app/three.txt", b"c")]);

        let outer = dir.path().join("image.tar");
        write_tar(
            &outer,
            &[
                ("manifest.json", br#"[{"Config":"cfg.json","Layers":["layer1.tar","layer2.tar"]}]"#),
                ("layer1.tar", &fs::read(dir.path().join("layer1.tar")).unwrap()),
                ("layer2.tar", &fs::read(dir.path().join("layer2.tar")).unwrap()),
            ],
        );

        let squashed = squash_image(&outer, &ExtractOptions::default()).unwrap();
        assert!(!squashed.root.path().join("app/one.txt").exists());
        assert!(!squashed.root.path().join("app/two.txt").exists());
        assert!(squashed.root.path().join("app/three.txt").exists(), "the opaque layer's own file must still be applied");
    }

    #[test]
    fn squashes_an_oci_layout_directory_via_index_and_manifest_blobs() {
        let dir = tempfile::tempdir().unwrap();
        write_tar(&dir.path().join("layer.tar"), &[("bin/app", b"the app")]);
        let layer_bytes = fs::read(dir.path().join("layer.tar")).unwrap();

        let layout = dir.path().join("layout");
        fs::create_dir_all(layout.join("blobs/sha256")).unwrap();
        fs::write(layout.join("oci-layout"), r#"{"imageLayoutVersion":"1.0.0"}"#).unwrap();
        fs::write(layout.join("blobs/sha256/layerdigest"), &layer_bytes).unwrap();
        fs::write(
            layout.join("blobs/sha256/manifestdigest"),
            r#"{"schemaVersion":2,"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar","digest":"sha256:layerdigest","size":1}]}"#,
        )
        .unwrap();
        fs::write(
            layout.join("index.json"),
            r#"{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:manifestdigest","size":1}]}"#,
        )
        .unwrap();

        let squashed = squash_image(&layout, &ExtractOptions::default()).unwrap();
        assert_eq!(squashed.report.layer_count, 1);
        assert_eq!(fs::read_to_string(squashed.root.path().join("bin/app")).unwrap(), "the app");
    }
}
