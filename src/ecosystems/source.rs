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
    // PEP 508 direct reference: `name @ url`. Split on the first `@`, which is
    // the reference marker; any committish `@ref` lives inside the URL.
    let target = match s.find('@') {
        Some(idx) => s[idx + 1..].trim(),
        None => s,
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

fn is_path_spec(s: &str) -> bool {
    s.starts_with("file:")
        || s.starts_with("link:")
        || s.starts_with("portal:")
        || s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with('/')
        || s.starts_with("~/")
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
        Some((_, committish)) if !committish.contains('/') => is_pinned_ref(committish),
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
