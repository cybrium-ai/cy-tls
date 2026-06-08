//! v0.5.71 — `cy-tls update` / `cy-tls upgrade` self-update.
//!
//! Matches the cyweb / cyred / cyproxy pattern: hit GitHub Releases API,
//! compare `CARGO_PKG_VERSION` to the latest tag, download the matching
//! per-platform binary, backup-replace-chmod the running executable.
//! Synchronous (ureq) so we don't pull reqwest just for this; runs from
//! the CLI command handler in main.rs.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Result};

const LATEST_URL: &str = "https://api.github.com/repos/cybrium-ai/cy-tls/releases/latest";

/// Run the self-update flow. Prints progress to stderr; returns Ok(())
/// when up-to-date OR when the upgrade succeeded. Returns Err on
/// network / IO / permission failure so the CLI can exit non-zero.
pub fn run() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    eprintln!("cy-tls update: current version {current}");
    eprintln!("Checking https://github.com/cybrium-ai/cy-tls/releases/latest ...");

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .user_agent(&format!("cy-tls/{current}"))
        .build();

    let body = agent
        .get(LATEST_URL)
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| anyhow!("GitHub API request failed: {e}"))?
        .into_string()
        .map_err(|e| anyhow!("GitHub API body read failed: {e}"))?;

    let release: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| anyhow!("GitHub API JSON parse failed: {e}"))?;
    let latest = release["tag_name"]
        .as_str()
        .unwrap_or("")
        .trim_start_matches('v');
    if latest.is_empty() {
        return Err(anyhow!("GitHub API returned no tag_name"));
    }

    if latest == current {
        eprintln!("Already up to date (v{current}).");
        return Ok(());
    }

    eprintln!("New version available: v{current} → v{latest}");

    let binary_name = host_binary_name()
        .ok_or_else(|| anyhow!("no prebuilt binary published for this host triple"))?;

    let download_url = release["assets"]
        .as_array()
        .and_then(|assets| {
            assets.iter().find_map(|a| {
                let name = a["name"].as_str()?;
                if name == binary_name {
                    a["browser_download_url"].as_str().map(String::from)
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| anyhow!("no asset named {binary_name} in release v{latest}"))?;

    eprintln!("Downloading {binary_name} ...");
    let bytes = {
        let mut buf: Vec<u8> = Vec::new();
        agent
            .get(&download_url)
            .call()
            .map_err(|e| anyhow!("download failed: {e}"))?
            .into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| anyhow!("download read failed: {e}"))?;
        buf
    };
    if bytes.is_empty() {
        return Err(anyhow!("download returned empty body"));
    }
    eprintln!("Downloaded {} bytes.", bytes.len());

    let exe_path: PathBuf = std::env::current_exe()
        .map_err(|e| anyhow!("cannot determine current executable path: {e}"))?;
    let backup = exe_path.with_extension("old");

    // Atomic-ish swap: move current → .old, write new in place, chmod,
    // delete .old on success. On failure restore the .old.
    std::fs::rename(&exe_path, &backup).map_err(|e| {
        anyhow!(
            "cannot rename {} → {} ({}). Try: sudo cy-tls update",
            exe_path.display(),
            backup.display(),
            e
        )
    })?;
    if let Err(e) = std::fs::write(&exe_path, &bytes) {
        let _ = std::fs::rename(&backup, &exe_path);
        return Err(anyhow!("cannot write new binary: {e}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&exe_path, std::fs::Permissions::from_mode(0o755));
    }
    let _ = std::fs::remove_file(&backup);

    eprintln!("Upgraded to v{latest} at {}.", exe_path.display());
    Ok(())
}

fn host_binary_name() -> Option<&'static str> {
    Some(match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "cy-tls-darwin-arm64",
        ("macos", "x86_64") => "cy-tls-darwin-amd64",
        ("linux", "aarch64") => "cy-tls-linux-arm64",
        ("linux", "x86_64") => "cy-tls-linux-amd64",
        ("windows", "x86_64") => "cy-tls-windows-amd64.exe",
        ("windows", "aarch64") => "cy-tls-windows-arm64.exe",
        _ => return None,
    })
}
