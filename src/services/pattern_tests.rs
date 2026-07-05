#[cfg(test)]
mod pattern_tests {
    use crate::models::sidecar::{SlitherDetector, SlitherElement, SlitherReport};
    use crate::models::vuln_ontology::{EdgeRelation, VulnClass, VulnNodeType};
    use crate::services::pattern::PatternAbstractor;

    fn det(check: &str, impact: &str, elems: Vec<(&str, &str)>) -> SlitherDetector {
        SlitherDetector {
            check: check.to_string(),
            impact: impact.to_string(),
            confidence: "High".to_string(),
            description: "test".to_string(),
            elements: elems
                .into_iter()
                .map(|(ty, name)| SlitherElement {
                    element_type: ty.to_string(),
                    name: name.to_string(),
                    source_mapping: None,
                })
                .collect(),
        }
    }

    fn rep(ds: Vec<SlitherDetector>) -> SlitherReport {
        SlitherReport {
            success: true,
            detectors: ds,
        }
    }

    // ── map_check_to_class

    #[test]
    fn reentrancy_variants() {
        for c in &[
            "reentrancy-eth",
            "reentrancy-no-eth",
            "reentrancy-benign",
            "reentrancy-unlimited-gas",
            "reentrancy-events",
        ] {
            assert_eq!(PatternAbstractor::map_check_to_class(c), VulnClass::Reentrancy);
        }
    }

    #[test]
    fn access_control_variants() {
        for c in &[
            "arbitrary-send-erc20",
            "arbitrary-send-eth",
            "controlled-delegatecall",
            "suicidal",
        ] {
            assert_eq!(
                PatternAbstractor::map_check_to_class(c),
                VulnClass::AccessControl
            );
        }
    }

    #[test]
    fn unknown_is_other() {
        assert_eq!(
            PatternAbstractor::map_check_to_class("novel-thing"),
            VulnClass::Other("novel-thing".into())
        );
    }

    // ── extract_pattern

    #[test]
    fn reentrancy_edges() {
        let d = det(
            "reentrancy-eth",
            "High",
            vec![
                ("function", "withdraw"),
                ("node", "ext_call"),
                ("variable", "balances"),
            ],
        );
        let p = PatternAbstractor::extract_pattern(&d);
        assert_eq!(p.nodes.len(), 4); // 1 class + 3 elements
        assert!(p.edges.iter().any(|e| e.relation == EdgeRelation::Writes));
        assert!(p.edges.iter().any(|e| e.relation == EdgeRelation::Calls));
        assert!(p.edges.iter().any(|e| e.relation == EdgeRelation::ClassifiedAs));
    }

    #[test]
    fn access_control_no_call_edges() {
        let d = det(
            "arbitrary-send-eth",
            "High",
            vec![("function", "f"), ("variable", "v")],
        );
        let p = PatternAbstractor::extract_pattern(&d);
        let calls = p.edges.iter().filter(|e| e.relation == EdgeRelation::Calls).count();
        assert_eq!(calls, 0);
        assert!(p.edges.iter().any(|e| e.relation == EdgeRelation::Writes));
    }

    #[test]
    fn unchecked_return_call_edges() {
        let d = det(
            "unchecked-lowlevel",
            "Medium",
            vec![("function", "send"), ("node", "call")],
        );
        let p = PatternAbstractor::extract_pattern(&d);
        assert_eq!(p.vuln_class, VulnClass::UncheckedReturn);
        assert!(p.edges.iter().any(|e| e.relation == EdgeRelation::Calls));
    }

    #[test]
    fn overflow_read_edges() {
        let d = det(
            "divide-before-multiply",
            "Low",
            vec![("function", "calc"), ("variable", "m")],
        );
        let p = PatternAbstractor::extract_pattern(&d);
        assert_eq!(p.vuln_class, VulnClass::ArithmeticOverflow);
        assert!(p.edges.iter().any(|e| e.relation == EdgeRelation::Reads));
    }

    #[test]
    fn anonymized_labels_sequential() {
        let d = det(
            "timestamp",
            "Low",
            vec![
                ("function", "a"),
                ("function", "b"),
                ("function", "c"),
            ],
        );
        let p = PatternAbstractor::extract_pattern(&d);
        let labels: Vec<&str> = p
            .nodes
            .iter()
            .filter(|n| n.node_type == VulnNodeType::Function)
            .map(|n| n.label.as_str())
            .collect();
        assert_eq!(labels, vec!["fn_0", "fn_1", "fn_2"]);
    }

    #[test]
    fn empty_report_no_patterns() {
        assert!(PatternAbstractor::extract(&rep(vec![])).is_empty());
    }

    #[test]
    fn two_detectors_two_patterns() {
        let r = rep(vec![
            det("reentrancy-eth", "High", vec![("function", "f1")]),
            det("timestamp", "Low", vec![("function", "f2")]),
        ]);
        let ps = PatternAbstractor::extract(&r);
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0].vuln_class, VulnClass::Reentrancy);
        assert_eq!(ps[1].vuln_class, VulnClass::TimestampDependence);
    }

    #[test]
    fn unknown_class_default_call_chain() {
        let d = det(
            "unknown-check",
            "Info",
            vec![
                ("function", "outer"),
                ("function", "middle"),
                ("function", "inner"),
            ],
        );
        let p = PatternAbstractor::extract_pattern(&d);
        assert_eq!(
            p.vuln_class,
            VulnClass::Other("unknown-check".into())
        );
        // fn_0 → fn_1 → fn_2 (2 pure call edges, excluding ClassifiedAs)
        let call_chains: Vec<_> = p
            .edges
            .iter()
            .filter(|e| {
                e.relation == EdgeRelation::Calls
                    && p.nodes.iter().any(|n| n.id == e.from && n.node_type == VulnNodeType::Function)
                    && p.nodes.iter().any(|n| n.id == e.to && n.node_type == VulnNodeType::Function)
            })
            .collect();
        assert_eq!(call_chains.len(), 2);
    }
}