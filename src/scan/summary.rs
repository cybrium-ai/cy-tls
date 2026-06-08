//! v0.5.58 — Top-of-report summary block. Pre-computes everything a
//! dashboard would otherwise build by iterating findings.

use serde::Serialize;

use super::grade::GradeReport;
use crate::finding::{Finding, Severity};

#[derive(Debug, Default, Clone, Serialize)]
pub struct SeverityCounts {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub info: u32,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct ScanSummary {
    /// Per-severity counts so dashboards can render the banner without
    /// iterating `findings`.
    pub severity_counts: SeverityCounts,
    /// Total finding count across all severities.
    pub total_findings: u32,
    /// True when the composite grade is A or better AND there are zero
    /// critical-severity findings. The headline "did this host pass"
    /// boolean that customer-facing summaries pivot on.
    pub passed: bool,
    /// Plain-English one-liner suitable for a banner or alert title.
    /// e.g. "Grade A+ — strong posture, 2 informational signals" or
    /// "Grade F — TLS 1.0 + Heartbleed detected; immediate remediation
    /// required".
    pub verdict_line: String,
    /// Subset of finding IDs that operators should treat as ACTIVE
    /// BREACH indicators (vs hardening recommendations). When this is
    /// non-empty, the host is actively exposed — Heartbleed leaking
    /// memory, ROBOT decrypting, DROWN cross-protocol etc. Cymind /
    /// Cybrium's auto-fix layer reads this to know what to contain.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub breach_indicators: Vec<String>,
}

/// Active-breach finding IDs — these signal *exploitable now*, not
/// "hardening gap". Used to populate breach_indicators and to flip
/// `passed` to false regardless of grade.
const BREACH_INDICATORS: &[&str] = &[
    "TLS-HEARTBLEED",
    "TLS-CCS-INJECTION",
    "TLS-ROBOT-VULNERABLE",
    "TLS-DROWN-VULNERABLE",
    "TLS-TICKETBLEED",
    "TLS-OPENSSL-PADDING-ORACLE",
    "TLS-GOLDENDOODLE-ACTIVE",
    "TLS-OCSP-REVOKED",
    "TLS-CERT-EXPIRED",
    "TLS-CERT-INTERMEDIATE-EXPIRED",
    "TLS-CERT-HOSTNAME-MISMATCH",
    "TLS-CERT-SELF-SIGNED",
    "TLS-CERT-LEAF-IS-CA",
    "TLS-SSLV2",
    "TLS-SSLV3",
    "TLS-RC4-CIPHER",
    "TLS-NULL-CIPHER",
    "TLS-EXPORT-CIPHER",
    "TLS-ANON-CIPHER",
];

pub fn compute(findings: &[Finding], grade: &GradeReport) -> ScanSummary {
    let mut counts = SeverityCounts::default();
    let mut breaches: Vec<String> = Vec::new();
    for f in findings {
        match f.severity {
            Severity::Critical => counts.critical += 1,
            Severity::High => counts.high += 1,
            Severity::Medium => counts.medium += 1,
            Severity::Low => counts.low += 1,
            Severity::Info => counts.info += 1,
        }
        if BREACH_INDICATORS.contains(&f.id) {
            breaches.push(f.id.to_string());
        }
    }
    let total = counts.critical + counts.high + counts.medium + counts.low + counts.info;

    let grade_is_passing = matches!(grade.grade.as_str(), "A+" | "A" | "A-");
    let passed = grade_is_passing && counts.critical == 0 && breaches.is_empty();

    let verdict_line = build_verdict_line(&counts, total, grade, &breaches, passed);

    ScanSummary {
        severity_counts: counts,
        total_findings: total,
        passed,
        verdict_line,
        breach_indicators: breaches,
    }
}

fn build_verdict_line(
    counts: &SeverityCounts,
    total: u32,
    grade: &GradeReport,
    breaches: &[String],
    passed: bool,
) -> String {
    let grade_str = if grade.grade.is_empty() {
        "ungraded"
    } else {
        grade.grade.as_str()
    };
    if !breaches.is_empty() {
        let primary = breaches[0]
            .trim_start_matches("TLS-")
            .trim_start_matches("CERT-")
            .replace('-', " ")
            .to_ascii_lowercase();
        return format!(
            "Grade {grade_str} — ACTIVE BREACH INDICATORS ({primary}{}); immediate containment required",
            if breaches.len() > 1 {
                format!(" +{} more", breaches.len() - 1)
            } else {
                String::new()
            }
        );
    }
    if !passed {
        return format!(
            "Grade {grade_str} — {} critical / {} high finding(s); not passing",
            counts.critical, counts.high
        );
    }
    if total == 0 {
        return format!("Grade {grade_str} — clean scan, no findings");
    }
    if counts.high + counts.medium == 0 {
        return format!(
            "Grade {grade_str} — strong posture, {} low/informational signal(s)",
            counts.low + counts.info
        );
    }
    format!(
        "Grade {grade_str} — {} medium / {} low / {} info finding(s)",
        counts.medium, counts.low, counts.info
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &'static str, sev: Severity) -> Finding {
        Finding {
            id,
            severity: sev,
            title: "test",
            host: "h".to_string(),
            evidence: "e".to_string(),
            controls: Vec::new(),
            remediation: "",
            reference_url: "",
        }
    }

    fn grade_str(s: &str) -> GradeReport {
        GradeReport {
            grade: s.into(),
            ..Default::default()
        }
    }

    #[test]
    fn clean_scan_passes() {
        let s = compute(&[], &grade_str("A+"));
        assert!(s.passed);
        assert_eq!(s.total_findings, 0);
        assert!(s.verdict_line.contains("clean"));
    }

    #[test]
    fn breach_blocks_pass() {
        let s = compute(
            &[finding("TLS-HEARTBLEED", Severity::Critical)],
            &grade_str("A+"),
        );
        assert!(!s.passed);
        assert_eq!(s.breach_indicators, vec!["TLS-HEARTBLEED"]);
        assert!(s.verdict_line.contains("ACTIVE BREACH"));
    }

    #[test]
    fn medium_findings_dont_block() {
        let s = compute(
            &[finding("HTTP-COOKIE-NO-SECURE", Severity::Medium)],
            &grade_str("A"),
        );
        assert!(s.passed);
        assert_eq!(s.severity_counts.medium, 1);
    }
}
