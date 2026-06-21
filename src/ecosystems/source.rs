//! Dependency source classification.
//!
//! Normalizes a dependency's version/spec string into a [`DependencySource`] so
//! SD006 can reason about where a package comes from rather than re-parsing
//! manager-specific syntax. JavaScript (npm/Yarn/pnpm/Bun `package.json` values)
//! and Python (PEP 508 / `requirements.txt`) use different spec grammars, so each
//! has its own classifier feeding the same enum.

/// Which dependency group a declaration belongs to. SD006 treats the production
/// closure more strictly than development dependencies. (Peer dependencies are
/// not extracted: they declare a host-provided contract, not an install.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DependencyGroup {
    Production,
    Development,
    Optional,
}

impl DependencyGroup {
    pub fn as_str(&self) -> &'static str {
        match self {
            DependencyGroup::Production => "production",
            DependencyGroup::Development => "development",
            DependencyGroup::Optional => "optional",
        }
    }

    /// Whether this group ships in the production dependency closure.
    pub fn is_production(&self) -> bool {
        matches!(
            self,
            DependencyGroup::Production | DependencyGroup::Optional
        )
    }
}

/// Where a dependency resolves from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DependencySource {
    /// A normal registry/semver/tag spec (the safe default).
    Registry,
    /// A VCS dependency. `floating` is true when it is not pinned to a commit
    /// (a branch ref or no ref at all); `ssh` is true for SSH transports.
    Git { floating: bool, ssh: bool },
    /// A local filesystem path dependency.
    Path,
    /// A direct tarball/archive URL.
    Tarball,
    /// An internal workspace/catalog reference (never a finding).
    Workspace,
}

/// A single declared dependency, normalized across ecosystems.
#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub spec: String,
    pub group: DependencyGroup,
    pub source: DependencySource,
    /// The manifest the declaration came from, so findings point at the right
    /// file (e.g. a specific `requirements*.txt`, not the project's first one).
    pub file: std::path::PathBuf,
}

/// Classifies a JavaScript `package.json` dependency value.
pub fn classify_js_source(spec: &str) -> DependencySource {
    let s = spec.trim();
    if s.starts_with("workspace:") || s.starts_with("catalog:") {
        return DependencySource::Workspace;
    }
    // `npm:alias@range` is still a registry install.
    if s.starts_with("npm:") {
        return DependencySource::Registry;
    }
    if is_path_spec(s) {
        return DependencySource::Path;
    }
    if let Some(src) = git_url_source(s) {
        return src;
    }
    // Host shorthands: `github:u/r`, `gitlab:u/r`, `bitbucket:u/r`, `gist:id`.
    if ["github:", "gitlab:", "bitbucket:", "gist:"]
        .iter()
        .any(|p| s.starts_with(p))
    {
        return DependencySource::Git {
            floating: !has_pinned_committish(s),
            ssh: false,
        };
    }
    // scp-like SSH: `git@github.com:user/repo.git#ref`.
    if s.starts_with("git@") && s.contains(':') {
        return DependencySource::Git {
            floating: !has_pinned_committish(s),
            ssh: true,
        };
    }
    if s.starts_with("http://") || s.starts_with("https://") {
        // npm/Yarn also accept HTTPS Git URLs (`https://host/repo.git#<ref>`);
        // classify those as Git so a pinned ref is not a false-positive tarball.
        if is_git_http_url(s) {
            return DependencySource::Git {
                floating: !has_pinned_committish(s),
                ssh: false,
            };
        }
        return DependencySource::Tarball;
    }
    // `user/repo` or `user/repo#ref` GitHub shorthand.
    if is_github_shorthand(s) {
        return DependencySource::Git {
            floating: !has_pinned_committish(s),
            ssh: false,
        };
    }
    DependencySource::Registry
}

/// Classifies a Python PEP 508 / `requirements.txt` dependency spec.
pub fn classify_python_source(spec: &str) -> DependencySource {
    let mut s = spec.trim();
    // `-e <target>` editable installs (requirements.txt).
    if let Some(rest) = s.strip_prefix("-e ") {
        s = rest.trim();
    }
    // A bare URL/path (common with `-e`) is the target as-is; splitting it on
    // `@` would wrongly treat SSH userinfo (`git+ssh://git@host/…`) as the
    // PEP 508 direct-reference marker. Only a `name @ url` form is split, on its
    // first `@` (a distribution name never contains `@`).
    let target = if is_python_url_or_path(s) {
        s
    } else {
        match s.find('@') {
            Some(idx) => s[idx + 1..].trim(),
            None => s,
        }
    };
    if target.starts_with("git+") || target.starts_with("git://") {
        return DependencySource::Git {
            floating: !python_git_pinned(target),
            ssh: target.starts_with("git+ssh"),
        };
    }
    if target.starts_with("ssh://") {
        return DependencySource::Git {
            floating: !python_git_pinned(target),
            ssh: true,
        };
    }
    if target.starts_with("file://") || is_path_spec(target) {
        return DependencySource::Path;
    }
    if target.starts_with("http://") || target.starts_with("https://") {
        return DependencySource::Tarball;
    }
    DependencySource::Registry
}

/// Classifies a Cargo dependency value from `Cargo.toml`. The value is either a
/// version string (`"1.0"`, a registry requirement) or an inline table that may
/// carry `path`, `git` (+ `rev`/`tag`/`branch`), or `workspace`.
pub fn classify_cargo_dependency(value: &toml::Value) -> DependencySource {
    if value.is_str() {
        return DependencySource::Registry;
    }
    let Some(table) = value.as_table() else {
        return DependencySource::Registry;
    };
    if table.get("workspace").and_then(|v| v.as_bool()) == Some(true) {
        return DependencySource::Workspace;
    }
    if table.contains_key("path") {
        return DependencySource::Path;
    }
    if let Some(git) = table.get("git").and_then(|v| v.as_str()) {
        // Pinned by a commit `rev`, or by a `tag` that names an immutable
        // release (a version tag or SHA). A `branch`, an arbitrary moving tag
        // (`latest`, `nightly`), or no ref at all tracks a moving target — same
        // pinned/floating test the JS/Python classifiers use. Cargo `git =`
        // fields are full URLs, so SSH is just the `ssh://` scheme.
        let pinned = table.contains_key("rev")
            || table
                .get("tag")
                .and_then(|v| v.as_str())
                .is_some_and(is_pinned_ref);
        return DependencySource::Git {
            floating: !pinned,
            ssh: git.starts_with("ssh://"),
        };
    }
    DependencySource::Registry
}

/// Classifies the right-hand side of a Go `replace` directive. A local
/// filesystem path is unsafe (replace directives are ignored outside the main
/// module, so consumers cannot resolve it); a replacement to another module is
/// still proxy-resolved and checksummed.
pub fn classify_go_replace_target(target: &str) -> DependencySource {
    let t = target.trim();
    let is_local = t.starts_with("./")
        || t.starts_with("../")
        || t.starts_with('/')
        || t.starts_with(".\\")
        || t.starts_with("..\\")
        || is_windows_abs_path(t);
    if is_local {
        DependencySource::Path
    } else {
        DependencySource::Registry
    }
}

/// Whether a path is a Windows drive-absolute path like `C:\dev` or `C:/dev`.
fn is_windows_abs_path(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')
}

fn is_path_spec(s: &str) -> bool {
    s.starts_with("file:")
        || s.starts_with("link:")
        || s.starts_with("portal:")
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('/')
        || s.starts_with("~/")
}

/// Whether an `http(s)://` spec is actually a Git URL (its path ends in `.git`,
/// ignoring any `#committish`).
fn is_git_http_url(s: &str) -> bool {
    // Strip a `#committish` and/or `?query` before testing the `.git` suffix, so
    // a tarball URL with a `?file=…git` query is not misread as Git.
    let path = s.split(['#', '?']).next().unwrap_or(s);
    path.ends_with(".git")
}

/// Whether a Python spec is itself a bare URL or path (no `name @` prefix).
fn is_python_url_or_path(s: &str) -> bool {
    s.starts_with("git+")
        || s.starts_with("git://")
        || s.starts_with("ssh://")
        || s.starts_with("http://")
        || s.starts_with("https://")
        || is_path_spec(s)
}

/// Recognizes explicit git URL schemes (`git+https://`, `git://`, …).
fn git_url_source(s: &str) -> Option<DependencySource> {
    let is_git = s.starts_with("git+") || s.starts_with("git://") || s.starts_with("ssh://");
    if !is_git {
        return None;
    }
    Some(DependencySource::Git {
        floating: !has_pinned_committish(s),
        ssh: s.contains("ssh://") || s.starts_with("git+ssh"),
    })
}

/// Whether a JS git spec is pinned to a commit or version tag via `#ref`.
/// A branch ref, a `#semver:` range, or no ref at all is treated as floating.
fn has_pinned_committish(s: &str) -> bool {
    match s.rsplit_once('#') {
        Some((_, committish)) => is_pinned_ref(committish),
        None => false,
    }
}

/// Whether a Python git URL is pinned via a trailing `@ref` after the scheme.
fn python_git_pinned(url: &str) -> bool {
    // The committish is the `@ref` after the repo path. A `@` belonging to SSH
    // userinfo (`git+ssh://git@host/...`) sits before the path, so its trailing
    // segment still contains `/`; a real committish never does.
    let after_scheme = url.split_once("://").map(|x| x.1).unwrap_or(url);
    match after_scheme.rsplit_once('@') {
        Some((_, committish)) if !committish.contains('/') => {
            // Trim a trailing `#subdirectory=…` fragment or ` ; env marker` that
            // PEP 508 allows after the committish, so a pinned ref still reads as
            // pinned.
            let end = committish
                .find(['#', ';', ' ', '\t'])
                .unwrap_or(committish.len());
            is_pinned_ref(&committish[..end])
        }
        _ => false,
    }
}

/// A ref is "pinned" if it is a commit SHA or a version tag; branch names and
/// ranges are floating.
fn is_pinned_ref(committish: &str) -> bool {
    let c = committish.trim();
    if c.is_empty() || c.starts_with("semver:") {
        return false;
    }
    // Commit SHA: 7-40 hex chars.
    let is_sha = (7..=40).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_hexdigit());
    // Version tag: `v1.2.3`, or a dotted number like `1.2.3`. A bare single
    // number (`2`) is treated as a (movable) branch, not a tag.
    let is_version = match c.strip_prefix('v') {
        // `v` prefix: a release tag even without dots (`v2`).
        Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit() || b == b'.'),
        // No `v`: require a dot so `2` stays floating but `1.2` is a tag.
        None => {
            c.contains('.')
                && c.bytes().next().is_some_and(|b| b.is_ascii_digit())
                && c.bytes().all(|b| b.is_ascii_digit() || b == b'.')
        }
    };
    is_sha || is_version
}

/// Whether `s` is a bare `owner/repo` (optionally `#ref`) GitHub shorthand.
fn is_github_shorthand(s: &str) -> bool {
    let core = s.split('#').next().unwrap_or(s);
    if core.starts_with('@') || core.contains("://") || core.contains(' ') {
        return false;
    }
    let mut parts = core.split('/');
    let (Some(owner), Some(repo), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let ok = |seg: &str| {
        !seg.is_empty()
            && seg
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    };
    ok(owner) && ok(repo)
}

#[cfg(test)]
mod tests {
    use super::DependencySource::*;
    use super::*;

    fn cargo(toml_value: &str) -> DependencySource {
        classify_cargo_dependency(&toml::from_str::<toml::Value>(toml_value).unwrap()["x"])
    }

    #[test]
    fn cargo_registry_and_workspace_are_safe() {
        assert_eq!(cargo("x = \"1.0\""), Registry);
        assert_eq!(cargo("x = { version = \"1.0\" }"), Registry);
        assert_eq!(cargo("x = { workspace = true }"), Workspace);
    }

    #[test]
    fn cargo_path_and_git_classification() {
        assert_eq!(cargo("x = { path = \"../x\" }"), Path);
        assert_eq!(
            cargo("x = { git = \"https://h/r.git\" }"),
            Git {
                floating: true,
                ssh: false
            }
        );
        assert_eq!(
            cargo("x = { git = \"https://h/r.git\", branch = \"main\" }"),
            Git {
                floating: true,
                ssh: false
            }
        );
        assert_eq!(
            cargo("x = { git = \"https://h/r.git\", rev = \"abc123\" }"),
            Git {
                floating: false,
                ssh: false
            }
        );
        assert_eq!(
            cargo("x = { git = \"https://h/r.git\", tag = \"v1.0\" }"),
            Git {
                floating: false,
                ssh: false
            }
        );
        // A moving (non-version) tag is floating, matching the JS/Python rule.
        assert_eq!(
            cargo("x = { git = \"https://h/r.git\", tag = \"latest\" }"),
            Git {
                floating: true,
                ssh: false
            }
        );
        assert_eq!(
            cargo("x = { git = \"ssh://git@h/r.git\" }"),
            Git {
                floating: true,
                ssh: true
            }
        );
    }

    #[test]
    fn go_windows_absolute_replace_is_path() {
        assert_eq!(classify_go_replace_target("C:\\dev\\local"), Path);
        assert_eq!(classify_go_replace_target("D:/dev/local"), Path);
    }

    #[test]
    fn go_replace_target_classification() {
        assert_eq!(classify_go_replace_target("../local"), Path);
        assert_eq!(classify_go_replace_target("./local"), Path);
        assert_eq!(classify_go_replace_target("/abs/path"), Path);
        assert_eq!(
            classify_go_replace_target("github.com/fork/x v1.2.3"),
            Registry
        );
    }

    #[test]
    fn js_registry_specs() {
        for s in [
            "^1.2.3",
            "~1",
            "1.x",
            "*",
            "latest",
            ">=1 <2",
            "npm:left-pad@^1",
        ] {
            assert_eq!(classify_js_source(s), Registry, "{s}");
        }
    }

    #[test]
    fn js_workspace_and_catalog_are_internal() {
        assert_eq!(classify_js_source("workspace:*"), Workspace);
        assert_eq!(classify_js_source("catalog:"), Workspace);
    }

    #[test]
    fn js_paths() {
        for s in ["file:../local", "link:../x", "./local", "../up", "/abs"] {
            assert_eq!(classify_js_source(s), Path, "{s}");
        }
    }

    #[test]
    fn js_git_floating_vs_pinned() {
        assert_eq!(
            classify_js_source("git+https://github.com/u/r.git"),
            Git {
                floating: true,
                ssh: false
            }
        );
        assert_eq!(
            classify_js_source("github:u/r#main"),
            Git {
                floating: true,
                ssh: false
            }
        );
        assert_eq!(
            classify_js_source("github:u/r#3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b"),
            Git {
                floating: false,
                ssh: false
            }
        );
        assert_eq!(
            classify_js_source("github:u/r#v1.2.3"),
            Git {
                floating: false,
                ssh: false
            }
        );
        assert_eq!(
            classify_js_source("u/r"),
            Git {
                floating: true,
                ssh: false
            }
        );
    }

    #[test]
    fn js_ssh_git() {
        assert_eq!(
            classify_js_source("git+ssh://git@github.com/u/r.git"),
            Git {
                floating: true,
                ssh: true
            }
        );
        assert_eq!(
            classify_js_source("git@github.com:u/r.git#abc1234"),
            Git {
                floating: false,
                ssh: true
            }
        );
    }

    #[test]
    fn js_tarball() {
        assert_eq!(classify_js_source("https://example.com/pkg.tgz"), Tarball);
    }

    #[test]
    fn js_https_git_url_is_git_not_tarball() {
        assert_eq!(
            classify_js_source(
                "https://github.com/org/repo.git#3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b"
            ),
            Git {
                floating: false,
                ssh: false
            }
        );
        assert_eq!(
            classify_js_source("https://github.com/org/repo.git#main"),
            Git {
                floating: true,
                ssh: false
            }
        );
    }

    #[test]
    fn python_committish_with_fragment_or_marker_stays_pinned() {
        assert_eq!(
            classify_python_source("mypkg @ git+https://h/r.git@v1.0.0#subdirectory=pkg"),
            Git {
                floating: false,
                ssh: false
            }
        );
        assert_eq!(
            classify_python_source("mypkg @ git+https://h/r.git@v1.0.0 ; python_version < \"3.8\""),
            Git {
                floating: false,
                ssh: false
            }
        );
    }

    #[test]
    fn js_query_tarball_is_not_git() {
        assert_eq!(
            classify_js_source("https://example.com/dl?file=pkg.git"),
            Tarball
        );
    }

    #[test]
    fn python_bare_editable_ssh_url_is_git() {
        // A bare URL (no `name @` prefix) must not be split on its SSH userinfo @.
        assert_eq!(
            classify_python_source("-e git+ssh://git@host/org/repo.git"),
            Git {
                floating: true,
                ssh: true
            }
        );
        assert_eq!(
            classify_python_source("git+https://h/r.git@v1.0.0"),
            Git {
                floating: false,
                ssh: false
            }
        );
    }

    #[test]
    fn python_specs() {
        assert_eq!(classify_python_source("requests>=2.0"), Registry);
        assert_eq!(classify_python_source("flask[async]==2.0"), Registry);
        assert_eq!(
            classify_python_source("mypkg @ git+https://h/r.git"),
            Git {
                floating: true,
                ssh: false
            }
        );
        assert_eq!(
            classify_python_source("mypkg @ git+https://h/r.git@v1.0.0"),
            Git {
                floating: false,
                ssh: false
            }
        );
        assert_eq!(
            classify_python_source("mypkg @ git+ssh://git@h/r.git@main"),
            Git {
                floating: true,
                ssh: true
            }
        );
        assert_eq!(classify_python_source("pkg @ https://h/p.whl"), Tarball);
        assert_eq!(classify_python_source("-e ./local"), Path);
        assert_eq!(classify_python_source("pkg @ file:///abs"), Path);
    }

    #[test]
    fn python_ssh_is_not_matched_by_substring() {
        // A repo named "ssh-utils" over https must not be flagged as SSH.
        assert_eq!(
            classify_python_source("pkg @ git+https://github.com/o/ssh-utils.git"),
            Git {
                floating: true,
                ssh: false
            }
        );
    }

    #[test]
    fn python_ssh_userinfo_at_is_not_a_committish() {
        // The `@` in `git@host` is userinfo, so this URL has no ref -> floating.
        assert_eq!(
            classify_python_source("pkg @ git+ssh://git@host/org/repo.git"),
            Git {
                floating: true,
                ssh: true
            }
        );
    }

    #[test]
    fn numeric_branch_is_floating_but_dotted_tag_is_pinned() {
        // `#2` is a movable branch; `#1.2` and `#v2` are release tags.
        assert_eq!(
            classify_js_source("github:u/r#2"),
            Git {
                floating: true,
                ssh: false
            }
        );
        assert_eq!(
            classify_js_source("github:u/r#1.2"),
            Git {
                floating: false,
                ssh: false
            }
        );
        assert_eq!(
            classify_js_source("github:u/r#v2"),
            Git {
                floating: false,
                ssh: false
            }
        );
    }
}
