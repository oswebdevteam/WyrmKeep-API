use crate::models::contract::ContractLanguage;
use crate::models::finding::FindingSeverity;
use crate::models::vuln_ontology::{AttackStep, CodeDiff, LineRange, VulnClass};
use super::rules::{self, RuleMatch};

#[derive(Debug, Clone)]
pub struct DetectedVulnerability {
    pub vuln_class: VulnClass,
    pub severity: FindingSeverity,
    pub description: String,
    pub affected_lines: Vec<LineRange>,
    pub affected_functions: Vec<String>,
    pub attack_path: Vec<AttackStep>,
    pub suggested_fix: Option<CodeDiff>,
    pub confidence: f32,
    pub check_name: String,
}

pub struct AnalysisEngine;

impl AnalysisEngine {
    pub fn analyze(source: &str, language: &ContractLanguage) -> Vec<DetectedVulnerability> {
        let rule_set = rules::rules_for(language);
        let mut vulnerabilities = Vec::new();

        for rule in &rule_set {
            let matches = rule.detect(source);
            for m in matches {
                vulnerabilities.push(Self::match_to_vulnerability(m, source));
            }
        }

        vulnerabilities.sort_by(|a, b| {
            severity_ordinal(&a.severity)
                .cmp(&severity_ordinal(&b.severity))
        });

        vulnerabilities
    }

    fn match_to_vulnerability(m: RuleMatch, source: &str) -> DetectedVulnerability {
        let suggested_fix = m.fix_hint.map(|hint| {
            let original = m.affected_lines.first().map(|lr| {
                extract_lines(source, lr.start, lr.end)
            }).unwrap_or_default();

            CodeDiff {
                original,
                patched: hint.patched,
                description: hint.explanation,
            }
        });

        let attack_path: Vec<AttackStep> = m.affected_functions
            .iter()
            .enumerate()
            .map(|(i, fname)| {
                let line_range = m.affected_lines.get(i).cloned();
                AttackStep {
                    order: i as u32,
                    function_name: fname.clone(),
                    action: m.action_hint.clone().unwrap_or_else(|| "call".into()),
                    line_range,
                }
            })
            .collect();

        DetectedVulnerability {
            vuln_class: m.vuln_class,
            severity: m.severity,
            description: m.description,
            affected_lines: m.affected_lines,
            affected_functions: m.affected_functions,
            attack_path,
            suggested_fix,
            confidence: m.confidence,
            check_name: m.check_name,
        }
    }
}

fn severity_ordinal(s: &FindingSeverity) -> u8 {
    match s {
        FindingSeverity::High => 0,
        FindingSeverity::Medium => 1,
        FindingSeverity::Low => 2,
        FindingSeverity::Informational => 3,
    }
}

fn extract_lines(source: &str, start: u32, end: u32) -> String {
    source
        .lines()
        .skip(start.saturating_sub(1) as usize)
        .take((end.saturating_sub(start) + 1) as usize)
        .collect::<Vec<_>>()
        .join("\n")
}
