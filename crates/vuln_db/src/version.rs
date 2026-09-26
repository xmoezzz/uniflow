//! Version ordering per package-manager family. Application ecosystems use
//! the lenient `versions::Versioning` order (see `range.rs`), but OS
//! package versions follow their package manager's own rules, and those
//! rules disagree with semver-ish ordering exactly where distro security
//! fixes live: `1.2.3-1+deb12u1` vs `1.2.3-1`, `1.0~rc1` < `1.0`, RPM
//! epochs (`1:1.0` > `2.0`), Alpine's `-r3` revisions and `_p1` patch
//! suffixes. Using the wrong comparator silently turns "fixed" into
//! "vulnerable" or back, so each family gets a faithful port of its
//! reference implementation:
//! - dpkg: `verrevcmp` from dpkg's `lib/dpkg/version.c`
//! - rpm: `rpmvercmp` from rpm's `rpmio/rpmvercmp.c` (incl. `~` and `^`)
//! - apk: apk-tools' `apk_version_compare` token rules
//!
//! Two application ecosystems also get their own rules, because the lenient
//! generic order is wrong exactly on pre-releases — where fixes often land:
//! - PyPI: PEP 440 (`1.0.dev1 < 1.0a1 < 1.0rc1 < 1.0 < 1.0.post1`, epochs,
//!   local versions); the generic order treats `1.0.0rc1` as equal to `1.0.0`
//! - Maven: `ComparableVersion` from maven-artifact (`1.0-alpha < 1.0-rc <
//!   1.0 = 1.0.Final = 1.0-ga < 1.0-sp1`, `-SNAPSHOT` below its release)
use std::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scheme {
    /// Application ecosystems (npm, PyPI, Maven, Go, ...).
    Generic,
    Dpkg,
    Rpm,
    Apk,
    Pep440,
    Maven,
}

impl Scheme {
    /// The comparator for a normalized ecosystem tag. OS ecosystems are
    /// `<distro>:<release>` (see `uniflow_os_package_db::Distro::data_keys`).
    pub fn for_ecosystem(ecosystem: &str) -> Scheme {
        let distro = ecosystem.split(':').next().unwrap_or(ecosystem);
        match distro {
            "debian" | "ubuntu" | "kylin-desktop" | "uos" | "deepin" => Scheme::Dpkg,
            "alpine" | "wolfi" | "chainguard" => Scheme::Apk,
            "rhel" | "centos" | "rocky" | "almalinux" | "ol" | "amzn" | "fedora" | "openeuler" | "anolis" | "opencloudos" | "kylin"
            | "uos-server" | "sles" | "opensuse-leap" | "opensuse-tumbleweed" | "azurelinux" | "mageia" | "photon" => Scheme::Rpm,
            "pypi" => Scheme::Pep440,
            "maven" => Scheme::Maven,
            _ => Scheme::Generic,
        }
    }
}

// ---------------------------------------------------------------- dpkg --

/// dpkg's character order for the non-digit parts: `~` sorts before
/// everything (even the end of the string), letters before non-letters.
fn dpkg_order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) => c as i32 + 256,
    }
}

fn verrevcmp(a: &[u8], b: &[u8]) -> Ordering {
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        let mut first_diff = 0;
        while (i < a.len() && !a[i].is_ascii_digit()) || (j < b.len() && !b[j].is_ascii_digit()) {
            let ac = dpkg_order(a.get(i).copied());
            let bc = dpkg_order(b.get(j).copied());
            if ac != bc {
                return ac.cmp(&bc);
            }
            i += 1;
            j += 1;
        }
        while i < a.len() && a[i] == b'0' {
            i += 1;
        }
        while j < b.len() && b[j] == b'0' {
            j += 1;
        }
        while i < a.len() && a[i].is_ascii_digit() && j < b.len() && b[j].is_ascii_digit() {
            if first_diff == 0 {
                first_diff = a[i] as i32 - b[j] as i32;
            }
            i += 1;
            j += 1;
        }
        if i < a.len() && a[i].is_ascii_digit() {
            return Ordering::Greater;
        }
        if j < b.len() && b[j].is_ascii_digit() {
            return Ordering::Less;
        }
        if first_diff != 0 {
            return first_diff.cmp(&0);
        }
    }
    Ordering::Equal
}

/// `[epoch:]upstream[-revision]` — the epoch is everything before the
/// first `:`, the revision everything after the *last* `-`.
fn split_dpkg(v: &str) -> (u64, &str, &str) {
    let (epoch, rest) = match v.split_once(':') {
        Some((e, rest)) if e.chars().all(|c| c.is_ascii_digit()) && !e.is_empty() => (e.parse().unwrap_or(0), rest),
        _ => (0, v),
    };
    match rest.rfind('-') {
        Some(idx) => (epoch, &rest[..idx], &rest[idx + 1..]),
        None => (epoch, rest, ""),
    }
}

pub fn dpkg_compare(a: &str, b: &str) -> Ordering {
    let (ea, ua, ra) = split_dpkg(a.trim());
    let (eb, ub, rb) = split_dpkg(b.trim());
    ea.cmp(&eb).then_with(|| verrevcmp(ua.as_bytes(), ub.as_bytes())).then_with(|| verrevcmp(ra.as_bytes(), rb.as_bytes()))
}

// ----------------------------------------------------------------- rpm --

/// rpm's segment comparison (`rpmvercmp`): alternating runs of digits and
/// letters, separators ignored; `~` sorts before everything (pre-release),
/// `^` after the base version but before any further segment (post-release
/// snapshot); a numeric segment beats an alphabetic one.
pub fn rpmvercmp(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0, 0);
    let is_sep = |c: u8| !c.is_ascii_alphanumeric() && c != b'~' && c != b'^';
    loop {
        while i < a.len() && is_sep(a[i]) {
            i += 1;
        }
        while j < b.len() && is_sep(b[j]) {
            j += 1;
        }
        let at = a.get(i).copied();
        let bt = b.get(j).copied();
        if at == Some(b'~') || bt == Some(b'~') {
            if at != Some(b'~') {
                return Ordering::Greater;
            }
            if bt != Some(b'~') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if at == Some(b'^') || bt == Some(b'^') {
            if at.is_none() {
                return Ordering::Less;
            }
            if bt.is_none() {
                return Ordering::Greater;
            }
            if at != Some(b'^') {
                return Ordering::Greater;
            }
            if bt != Some(b'^') {
                return Ordering::Less;
            }
            i += 1;
            j += 1;
            continue;
        }
        if at.is_none() || bt.is_none() {
            break;
        }
        let numeric = a[i].is_ascii_digit();
        let take = |s: &[u8], mut k: usize| {
            let start = k;
            while k < s.len() && if numeric { s[k].is_ascii_digit() } else { s[k].is_ascii_alphabetic() } {
                k += 1;
            }
            (start, k)
        };
        let (s1, e1) = take(a, i);
        let (s2, e2) = take(b, j);
        i = e1;
        j = e2;
        if s2 == e2 {
            // Segment types differ: numeric beats alphabetic.
            return if numeric { Ordering::Greater } else { Ordering::Less };
        }
        let (mut seg1, mut seg2) = (&a[s1..e1], &b[s2..e2]);
        if numeric {
            while seg1.first() == Some(&b'0') {
                seg1 = &seg1[1..];
            }
            while seg2.first() == Some(&b'0') {
                seg2 = &seg2[1..];
            }
            match seg1.len().cmp(&seg2.len()) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        match seg1.cmp(seg2) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    match (i >= a.len(), j >= b.len()) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        _ => Ordering::Greater,
    }
}

/// `[epoch:]version[-release]`, compared field by field; a missing epoch
/// is 0, and a missing release on either side compares equal (a bare
/// `1.2` range bound in an advisory matches any release of 1.2).
pub fn rpm_compare(a: &str, b: &str) -> Ordering {
    fn split(v: &str) -> (u64, &str, Option<&str>) {
        let (epoch, rest) = match v.split_once(':') {
            Some((e, rest)) if !e.is_empty() && e.chars().all(|c| c.is_ascii_digit()) => (e.parse().unwrap_or(0), rest),
            _ => (0, v),
        };
        match rest.rfind('-') {
            Some(idx) => (epoch, &rest[..idx], Some(&rest[idx + 1..])),
            None => (epoch, rest, None),
        }
    }
    let (ea, va, ra) = split(a.trim());
    let (eb, vb, rb) = split(b.trim());
    ea.cmp(&eb).then_with(|| rpmvercmp(va, vb)).then_with(|| match (ra, rb) {
        (Some(ra), Some(rb)) => rpmvercmp(ra, rb),
        _ => Ordering::Equal,
    })
}

// ----------------------------------------------------------------- apk --

/// apk-tools' suffix ranks: pre-release suffixes sort below the bare
/// version, post-release ones above it.
fn apk_suffix_rank(s: &str) -> Option<i32> {
    Some(match s {
        "alpha" => -4,
        "beta" => -3,
        "pre" => -2,
        "rc" => -1,
        "cvs" => 1,
        "svn" => 2,
        "git" => 3,
        "hg" => 4,
        "p" => 5,
        _ => return None,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum ApkToken<'a> {
    Num(&'a str),
    Letter(u8),
    Suffix(i32, &'a str),
    Revision(&'a str),
}

fn apk_tokens(v: &str) -> Vec<ApkToken<'_>> {
    let b = v.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let digits = |mut k: usize| {
        let s = k;
        while k < b.len() && b[k].is_ascii_digit() {
            k += 1;
        }
        (s, k)
    };
    while i < b.len() {
        match b[i] {
            c if c.is_ascii_digit() => {
                let (s, e) = digits(i);
                out.push(ApkToken::Num(&v[s..e]));
                i = e;
            }
            b'.' => i += 1,
            c if c.is_ascii_lowercase() => {
                out.push(ApkToken::Letter(c));
                i += 1;
            }
            b'_' => {
                let s = i + 1;
                let mut e = s;
                while e < b.len() && b[e].is_ascii_lowercase() {
                    e += 1;
                }
                let (ns, ne) = digits(e);
                let rank = apk_suffix_rank(&v[s..e]).unwrap_or(0);
                out.push(ApkToken::Suffix(rank, &v[ns..ne]));
                i = ne;
            }
            b'-' if b.get(i + 1) == Some(&b'r') => {
                let (s, e) = digits(i + 2);
                out.push(ApkToken::Revision(&v[s..e]));
                i = e;
            }
            _ => i += 1,
        }
    }
    out
}

fn kind_rank(token: &ApkToken<'_>) -> u8 {
    match token {
        ApkToken::Num(_) => 1,
        ApkToken::Letter(_) => 2,
        ApkToken::Suffix(..) => 3,
        ApkToken::Revision(_) => 5,
    }
}

fn cmp_numeric(a: &str, b: &str) -> Ordering {
    let a = a.trim_start_matches('0');
    let b = b.trim_start_matches('0');
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

pub fn apk_compare(a: &str, b: &str) -> Ordering {
    let ta = apk_tokens(a.trim());
    let tb = apk_tokens(b.trim());
    for k in 0..ta.len().max(tb.len()) {
        let ord = match (ta.get(k), tb.get(k)) {
            (Some(x), Some(y)) => match (x, y) {
                (ApkToken::Num(x), ApkToken::Num(y)) => cmp_numeric(x, y),
                (ApkToken::Letter(x), ApkToken::Letter(y)) => x.cmp(y),
                (ApkToken::Suffix(rx, nx), ApkToken::Suffix(ry, ny)) => rx.cmp(ry).then_with(|| cmp_numeric(nx, ny)),
                (ApkToken::Revision(x), ApkToken::Revision(y)) => cmp_numeric(x, y),
                // Different token kinds at the same position, as apk-tools
                // decides it: a pre-release suffix is older than anything;
                // otherwise the side whose next token is the *later* kind
                // (digit < letter < suffix < revision) is older — so
                // `1.0_p1` < `1.0.1` and `1.0-r0` < `1.0_git1-r0`.
                (ApkToken::Suffix(r, _), _) if *r < 0 => Ordering::Less,
                (_, ApkToken::Suffix(r, _)) if *r < 0 => Ordering::Greater,
                (x, y) => kind_rank(y).cmp(&kind_rank(x)),
            },
            // One side ran out: a trailing pre-release suffix makes the
            // longer one older (`1.0_rc1` < `1.0`), anything else newer.
            (Some(ApkToken::Suffix(r, _)), None) if *r < 0 => Ordering::Less,
            (None, Some(ApkToken::Suffix(r, _))) if *r < 0 => Ordering::Greater,
            (Some(_), None) => Ordering::Greater,
            (None, Some(_)) => Ordering::Less,
            (None, None) => Ordering::Equal,
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

// -------------------------------------------------------------- PEP 440 --

/// A parsed PEP 440 version, reduced to its sort key. Anything that isn't
/// valid PEP 440 (legacy `LegacyVersion` strings) sorts by plain text
/// after every valid version, as `packaging` did before it dropped them.
#[derive(Debug, PartialEq, Eq)]
struct Pep440 {
    epoch: u64,
    release: Vec<u64>,
    /// (phase, n): phase 0 = a, 1 = b, 2 = rc; `None` = no pre-release.
    pre: Option<(u8, u64)>,
    post: Option<u64>,
    dev: Option<u64>,
    local: Vec<LocalPart>,
}

#[derive(Debug, PartialEq, Eq)]
enum LocalPart {
    Num(u64),
    Text(String),
}

fn pep440_parse(raw: &str) -> Option<Pep440> {
    let s = raw.trim().to_ascii_lowercase();
    let s = s.strip_prefix('v').unwrap_or(&s);
    let (public, local) = match s.split_once('+') {
        Some((p, l)) => (p, Some(l)),
        None => (s, None),
    };
    let (epoch, rest) = match public.split_once('!') {
        Some((e, r)) => (e.parse().ok()?, r),
        None => (0, public),
    };
    let bytes = rest.as_bytes();
    let mut i = 0;
    let number = |i: &mut usize| -> Option<u64> {
        let start = *i;
        while *i < bytes.len() && bytes[*i].is_ascii_digit() {
            *i += 1;
        }
        if start == *i {
            None
        } else {
            rest[start..*i].parse().ok()
        }
    };
    let mut release = vec![number(&mut i)?];
    while i + 1 < bytes.len() && bytes[i] == b'.' && bytes[i + 1].is_ascii_digit() {
        i += 1;
        release.push(number(&mut i)?);
    }
    let skip_sep = |i: &mut usize| {
        if *i < bytes.len() && matches!(bytes[*i], b'.' | b'-' | b'_') {
            *i += 1;
        }
    };
    let word = |i: &mut usize| -> &str {
        let start = *i;
        while *i < bytes.len() && bytes[*i].is_ascii_alphabetic() {
            *i += 1;
        }
        &rest[start..*i]
    };
    let mut pre = None;
    let mut post = None;
    let mut dev = None;
    // Pre-release: a|alpha, b|beta, c|rc|pre|preview, optional separators
    // and an implicit 0.
    let save = i;
    skip_sep(&mut i);
    let phase = match word(&mut i) {
        "a" | "alpha" => Some(0),
        "b" | "beta" => Some(1),
        "c" | "rc" | "pre" | "preview" => Some(2),
        _ => None,
    };
    if let Some(phase) = phase {
        skip_sep(&mut i);
        pre = Some((phase, number(&mut i).unwrap_or(0)));
    } else {
        i = save;
    }
    // Post-release: `.post1`, `-rev1`, `-r1`, or the bare `-1` form.
    let save = i;
    if i < bytes.len() && bytes[i] == b'-' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
        i += 1;
        post = Some(number(&mut i)?);
    } else {
        skip_sep(&mut i);
        match word(&mut i) {
            "post" | "rev" | "r" => {
                skip_sep(&mut i);
                post = Some(number(&mut i).unwrap_or(0));
            }
            _ => i = save,
        }
    }
    let save = i;
    skip_sep(&mut i);
    if word(&mut i) == "dev" {
        skip_sep(&mut i);
        dev = Some(number(&mut i).unwrap_or(0));
    } else {
        i = save;
    }
    if i != bytes.len() {
        return None;
    }
    let local = local
        .map(|l| {
            l.split(['.', '-', '_'])
                .filter(|p| !p.is_empty())
                .map(|p| p.parse().map(LocalPart::Num).unwrap_or_else(|_| LocalPart::Text(p.to_string())))
                .collect()
        })
        .unwrap_or_default();
    Some(Pep440 { epoch, release, pre, post, dev, local })
}

fn pep440_key_cmp(a: &Pep440, b: &Pep440) -> Ordering {
    // Release compares with trailing zeros ignored (`1.0 == 1.0.0`).
    let trim = |r: &[u64]| -> usize { r.iter().rposition(|&x| x != 0).map_or(0, |p| p + 1) };
    let (ra, rb) = (&a.release[..trim(&a.release)], &b.release[..trim(&b.release)]);
    // Phase ranks: a dev-only release sorts before any pre-release of the
    // same version; no pre-release at all sorts after every one.
    let pre_key = |v: &Pep440| -> (i8, u64) {
        match (v.pre, v.post, v.dev) {
            (None, None, Some(_)) => (-1, 0),
            (None, _, _) => (3, 0),
            (Some((phase, n)), _, _) => (phase as i8, n),
        }
    };
    let post_key = |v: &Pep440| -> (i8, u64) { v.post.map_or((-1, 0), |n| (0, n)) };
    let dev_key = |v: &Pep440| -> (i8, u64) { v.dev.map_or((1, 0), |n| (0, n)) };
    a.epoch
        .cmp(&b.epoch)
        .then_with(|| ra.cmp(rb))
        .then_with(|| pre_key(a).cmp(&pre_key(b)))
        .then_with(|| post_key(a).cmp(&post_key(b)))
        .then_with(|| dev_key(a).cmp(&dev_key(b)))
        .then_with(|| {
            // Local segments: numbers sort after text; a longer local
            // version with an equal prefix is newer.
            for (x, y) in a.local.iter().zip(&b.local) {
                let ord = match (x, y) {
                    (LocalPart::Num(x), LocalPart::Num(y)) => x.cmp(y),
                    (LocalPart::Text(x), LocalPart::Text(y)) => x.cmp(y),
                    (LocalPart::Num(_), LocalPart::Text(_)) => Ordering::Greater,
                    (LocalPart::Text(_), LocalPart::Num(_)) => Ordering::Less,
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            a.local.len().cmp(&b.local.len())
        })
}

pub fn pep440_compare(a: &str, b: &str) -> Ordering {
    match (pep440_parse(a), pep440_parse(b)) {
        (Some(x), Some(y)) => pep440_key_cmp(&x, &y),
        (Some(_), None) => Ordering::Greater,
        (None, Some(_)) => Ordering::Less,
        (None, None) => a.cmp(b),
    }
}

// ---------------------------------------------------------------- Maven --

/// One item of Maven's `ComparableVersion`: numbers, qualifiers, and
/// `-`-introduced sub-lists.
#[derive(Debug, Clone)]
enum MvnItem {
    Int(u128),
    Str(String),
    List(Vec<MvnItem>),
}

/// Well-known qualifiers in release order; `""` (a plain release, with its
/// aliases ga/final/release) sits between `snapshot` and `sp`. Unknown
/// qualifiers sort after all of them, lexically.
fn mvn_qualifier_rank(q: &str) -> (u8, String) {
    let q = match q {
        "a" => "alpha",
        "b" => "beta",
        "m" => "milestone",
        "cr" => "rc",
        "ga" | "final" | "release" => "",
        other => other,
    };
    match q {
        "alpha" => (0, String::new()),
        "beta" => (1, String::new()),
        "milestone" => (2, String::new()),
        "rc" => (3, String::new()),
        "snapshot" => (4, String::new()),
        "" => (5, String::new()),
        "sp" => (6, String::new()),
        other => (7, other.to_string()),
    }
}

fn mvn_parse(raw: &str) -> Vec<MvnItem> {
    let s = raw.trim().to_ascii_lowercase();
    // Build a nested list: `.` separates items in the current list, `-`
    // (and a digit/letter transition) starts a sub-list.
    let mut stack: Vec<Vec<MvnItem>> = vec![Vec::new()];
    let mut token = String::new();
    let mut token_is_digit = false;
    let flush = |token: &mut String, is_digit: bool, list: &mut Vec<MvnItem>| {
        if token.is_empty() {
            // Maven turns an empty token into 0 (`1..2` = `1.0.2`).
            list.push(MvnItem::Int(0));
        } else if is_digit {
            list.push(MvnItem::Int(token.parse().unwrap_or(u128::MAX)));
        } else {
            // A qualifier directly followed by digits (`alpha1`) keeps its
            // short forms meaningful only in that position.
            list.push(MvnItem::Str(token.clone()));
        }
        token.clear();
    };
    let chars: Vec<char> = s.chars().collect();
    for (idx, &c) in chars.iter().enumerate() {
        if c == '.' {
            flush(&mut token, token_is_digit, stack.last_mut().unwrap());
        } else if c == '-' {
            flush(&mut token, token_is_digit, stack.last_mut().unwrap());
            stack.push(Vec::new());
        } else if c.is_ascii_digit() {
            if !token.is_empty() && !token_is_digit {
                // letter -> digit transition: `alpha1` is `alpha-1`.
                let letters = std::mem::take(&mut token);
                let qualifier_followed_by_digit = match letters.as_str() {
                    "a" => "alpha".to_string(),
                    "b" => "beta".to_string(),
                    "m" => "milestone".to_string(),
                    _ => letters,
                };
                stack.last_mut().unwrap().push(MvnItem::Str(qualifier_followed_by_digit));
                stack.push(Vec::new());
            }
            token_is_digit = true;
            token.push(c);
        } else {
            if !token.is_empty() && token_is_digit {
                // digit -> letter transition: `1rc` is `1-rc`.
                flush(&mut token, true, stack.last_mut().unwrap());
                stack.push(Vec::new());
            }
            token_is_digit = false;
            token.push(c);
        }
        let _ = idx;
    }
    if !token.is_empty() || chars.last().is_some_and(|c| *c == '.') {
        flush(&mut token, token_is_digit, stack.last_mut().unwrap());
    }
    while stack.len() > 1 {
        let inner = stack.pop().unwrap();
        stack.last_mut().unwrap().push(MvnItem::List(inner));
    }
    let mut root = stack.pop().unwrap_or_default();
    mvn_normalize(&mut root);
    root
}

/// Strips trailing "null" items (0, empty/release qualifiers, empty lists)
/// from every list, as `ComparableVersion` does: `1.0.0` = `1` = `1-ga`.
fn mvn_normalize(list: &mut Vec<MvnItem>) {
    for item in list.iter_mut() {
        if let MvnItem::List(inner) = item {
            mvn_normalize(inner);
        }
    }
    while list.last().is_some_and(mvn_is_null) {
        list.pop();
    }
}

fn mvn_is_null(item: &MvnItem) -> bool {
    match item {
        MvnItem::Int(n) => *n == 0,
        MvnItem::Str(s) => mvn_qualifier_rank(s).0 == 5,
        MvnItem::List(l) => l.is_empty(),
    }
}

fn mvn_cmp_item(a: Option<&MvnItem>, b: Option<&MvnItem>) -> Ordering {
    use MvnItem::*;
    match (a, b) {
        (None, None) => Ordering::Equal,
        // Compare against "nothing": a number > 0 is newer, a qualifier is
        // newer only if it ranks after a plain release, a list recurses.
        (Some(x), None) => match x {
            Int(n) => n.cmp(&0),
            Str(s) => mvn_qualifier_rank(s).cmp(&mvn_qualifier_rank("")),
            List(l) => mvn_cmp_list(l, &[]),
        },
        (None, Some(_)) => mvn_cmp_item(b, None).reverse(),
        (Some(Int(x)), Some(Int(y))) => x.cmp(y),
        (Some(Int(_)), Some(_)) => Ordering::Greater,
        (Some(Str(_)), Some(Int(_))) => Ordering::Less,
        (Some(Str(x)), Some(Str(y))) => mvn_qualifier_rank(x).cmp(&mvn_qualifier_rank(y)),
        (Some(Str(_)), Some(List(_))) => Ordering::Less,
        (Some(List(_)), Some(Int(_))) => Ordering::Less,
        (Some(List(_)), Some(Str(_))) => Ordering::Greater,
        (Some(List(x)), Some(List(y))) => mvn_cmp_list(x, y),
    }
}

fn mvn_cmp_list(a: &[MvnItem], b: &[MvnItem]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let ord = mvn_cmp_item(a.get(i), b.get(i));
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

pub fn maven_compare(a: &str, b: &str) -> Ordering {
    mvn_cmp_list(&mvn_parse(a), &mvn_parse(b))
}

/// The ordering for `scheme`; `Generic` is handled by the caller (it
/// needs `versions::Versioning`'s parsed form).
pub fn compare(scheme: Scheme, a: &str, b: &str) -> Ordering {
    match scheme {
        Scheme::Dpkg => dpkg_compare(a, b),
        Scheme::Rpm => rpm_compare(a, b),
        Scheme::Apk => apk_compare(a, b),
        Scheme::Pep440 => pep440_compare(a, b),
        Scheme::Maven => maven_compare(a, b),
        Scheme::Generic => a.cmp(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    #[test]
    fn pep440_orders_pre_post_dev_and_local_releases() {
        let ordered = [
            "1.0.dev0", "1.0a1.dev1", "1.0a1", "1.0a2", "1.0b1", "1.0rc1", "1.0", "1.0.post1.dev1", "1.0.post1", "1.0.post1+local.1", "1.1",
            "2!0.1",
        ];
        for pair in ordered.windows(2) {
            assert_eq!(pep440_compare(pair[0], pair[1]), Less, "{} < {}", pair[0], pair[1]);
        }
        for (a, b) in [("1.0", "1.0.0"), ("19.3b0", "19.3.0b0"), ("1.0-1", "1.0.post1"), ("1.0RC1", "1.0c1"), ("v2.0", "2.0")] {
            assert_eq!(pep440_compare(a, b), Equal, "{a} == {b}");
        }
        // The benchmark's miss: `black 19.3b0` is inside `< 24.3.0`.
        assert_eq!(pep440_compare("19.3b0", "24.3.0"), Less);
        assert_eq!(pep440_compare("1.0.0rc1", "1.0.0"), Less);
    }

    #[test]
    fn maven_matches_comparable_version_on_tricky_pairs() {
        // Orderings from maven-artifact's ComparableVersionTest.
        let ordered = ["1-alpha-1", "1-alpha-2", "1-beta-1", "1-milestone-1", "1-rc-1", "1-SNAPSHOT", "1", "1-sp-1", "1.0.1", "1.1", "1.10"];
        for pair in ordered.windows(2) {
            assert_eq!(maven_compare(pair[0], pair[1]), Less, "{} < {}", pair[0], pair[1]);
        }
        for (a, b) in [("1", "1.0.0"), ("1.0", "1-ga"), ("4.1.0.Final", "4.1.0"), ("1.0-RELEASE", "1.0"), ("1a1", "1-alpha-1")] {
            assert_eq!(maven_compare(a, b), Equal, "{a} == {b}");
        }
        assert_eq!(maven_compare("2.9.10.8", "2.9.10.7"), Greater);
        assert_eq!(maven_compare("5.3.18", "5.3.2"), Greater);
        assert_eq!(maven_compare("2.12.6.1", "2.13.0"), Less);
    }

    #[test]
    fn dpkg_matches_the_reference_implementation_on_tricky_pairs() {
        // Pairs from dpkg's own t/version test suite and real Debian fixes.
        for (a, b, want) in [
            ("1.0", "1.0", Equal),
            ("1.0~rc1", "1.0", Less),
            ("1.0~~", "1.0~", Less),
            ("1.0~", "1.0", Less),
            ("1.0", "1.0+deb12u1", Less),
            ("1.2.3-1", "1.2.3-1+deb12u1", Less),
            ("1:0.9", "2.0", Greater),
            ("2.30-1", "2.4-1", Greater),
            ("1.0-1", "1.0-1ubuntu0.1", Less),
            ("1.0a", "1.0", Greater),
            ("1.0", "1.0.0", Less),
            ("0:1.0", "1.0", Equal),
            ("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.15", Less),
            ("1.18.0-1", "1.18.0-1+deb12u1", Less),
            ("7.88.1-10+deb12u5", "7.88.1-10+deb12u12", Less),
            ("1.0-", "1.0", Equal),
        ] {
            assert_eq!(dpkg_compare(a, b), want, "{a} vs {b}");
            assert_eq!(dpkg_compare(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn rpm_matches_rpmvercmp_on_tricky_pairs() {
        // From rpm's tests/rpmvercmp.at.
        for (a, b, want) in [
            ("1.0", "1.0", Equal),
            ("1.0", "2.0", Less),
            ("2.0.1", "2.0", Greater),
            ("2.0.1a", "2.0.1", Greater),
            ("5.5p1", "5.5p2", Less),
            ("5.5p10", "5.5p1", Greater),
            ("10xyz", "10.1xyz", Less),
            ("xyz10", "xyz10.1", Less),
            ("1.0aa", "1.0a", Greater),
            ("1.0a", "1.0.1", Less),
            ("1.0~rc1", "1.0", Less),
            ("1.0~rc1", "1.0~rc2", Less),
            ("1.0~rc1~git123", "1.0~rc1", Less),
            ("1.0^", "1.0", Greater),
            ("1.0^git1", "1.0.1", Less),
            ("1.0^git1", "1.0^git2", Less),
            ("1.0^git1~pre", "1.0^git1", Less),
            ("2_0", "2_0", Equal),
            ("2.0", "2_0", Equal),
            ("a", "1", Less),
            ("001", "1", Equal),
        ] {
            assert_eq!(rpmvercmp(a, b), want, "{a} vs {b}");
        }
    }

    #[test]
    fn rpm_evr_uses_epoch_then_version_then_release() {
        assert_eq!(rpm_compare("1:1.0-1.el9", "2.0-1.el9"), Greater);
        assert_eq!(rpm_compare("0:10.2.6-23.el9_8.3", "10.2.6-23.el9_8.2"), Greater);
        assert_eq!(rpm_compare("3.0.7-27.el9", "3.0.7-27.el9_5.1"), Less);
        assert_eq!(rpm_compare("0.116-13.oe2003sp4", "0.116-12.oe2003sp4"), Greater);
        // A release-less bound matches every release of that version.
        assert_eq!(rpm_compare("1.2-5.el9", "1.2"), Equal);
    }

    #[test]
    fn apk_follows_apk_tools_ordering() {
        for (a, b, want) in [
            ("1.0", "1.0", Equal),
            ("1.0-r1", "1.0-r0", Greater),
            ("1.0-r10", "1.0-r9", Greater),
            ("1.0_rc1", "1.0", Less),
            ("1.0_alpha", "1.0_beta", Less),
            ("1.0_p1", "1.0", Greater),
            ("1.0_p1", "1.0.1", Less),
            ("1.2.3a", "1.2.3", Greater),
            ("1.2.3a", "1.2.4", Less),
            ("5.42.2-r1", "5.42.2-r0", Greater),
            ("3.1.4-r5", "3.1.10-r0", Less),
            ("2.39.3-r0", "2.39.3_git20240101-r0", Less),
        ] {
            assert_eq!(apk_compare(a, b), want, "{a} vs {b}");
            assert_eq!(apk_compare(b, a), want.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn schemes_are_picked_by_distro_prefix() {
        assert_eq!(Scheme::for_ecosystem("debian:12"), Scheme::Dpkg);
        assert_eq!(Scheme::for_ecosystem("ubuntu:22.04"), Scheme::Dpkg);
        assert_eq!(Scheme::for_ecosystem("alpine:3.19"), Scheme::Apk);
        assert_eq!(Scheme::for_ecosystem("rocky:9"), Scheme::Rpm);
        assert_eq!(Scheme::for_ecosystem("openeuler:22.03-lts-sp4"), Scheme::Rpm);
        assert_eq!(Scheme::for_ecosystem("npm"), Scheme::Generic);
    }
}
