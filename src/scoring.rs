//! Step 5: scoring.
//!
//! `risk_score = base_severity * reachable(1|0) * (1 + w * normalized_centrality)`,
//! clamped to `[0, 10]`. Reachability is a hard multiplicative gate (matches
//! the spec: "if a vulnerable function is unreachable, mark its risk score
//! as 0"), not an additive term — an unreachable vulnerability is zero
//! regardless of how severe or central it is.

use crate::models::{RiskAssessment, Vulnerability};

pub const DEFAULT_CENTRALITY_WEIGHT: f64 = 0.5;

/// Used only when OSV gave no numeric CVSS score and the raw vector isn't
/// parsed yet (see `osv_client::parse_cvss_vector_to_base_score`). Surfaced
/// explicitly as `base_severity` in the scorecard rather than silently
/// folded in, so it's never mistaken for a real CVSS score.
pub const UNSCORED_SEVERITY_PLACEHOLDER: f64 = 5.0;

pub fn compute_risk_score(
    vulnerability: &Vulnerability,
    reachable: bool,
    normalized_centrality: f64,
    centrality_weight: f64,
) -> RiskAssessment {
    let base_severity = vulnerability
        .severity_score
        .unwrap_or(UNSCORED_SEVERITY_PLACEHOLDER);
    let gate = if reachable { 1.0 } else { 0.0 };
    let risk_score =
        (base_severity * gate * (1.0 + centrality_weight * normalized_centrality)).clamp(0.0, 10.0);

    RiskAssessment {
        vulnerability: vulnerability.clone(),
        reachable,
        base_severity,
        centrality: normalized_centrality,
        centrality_weight,
        risk_score,
    }
}
