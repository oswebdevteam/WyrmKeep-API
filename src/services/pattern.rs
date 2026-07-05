use uuid::Uuid;
use std::collections::HashMap;

use crate::models::sidecar::{SlitherDetector, SlitherReport};
use crate::models::vuln_ontology::{
    AbstractPattern, EdgeRelation, VulnClass, VulnEdge, VulnNode, VulnNodeType,
};

pub struct PatternAbstractor;

impl PatternAbstractor {
    pub fn extract(report: &SlitherReport) -> Vec<AbstractPattern> {
        let mut patterns = Vec::new();

        for detector in &report.detectors {
            let pattern = Self::extract_pattern(detector);
            patterns.push(pattern);
        }

        patterns
    }

    pub(crate) fn extract_pattern(detector: &SlitherDetector) -> AbstractPattern {
        let vuln_class = Self::map_check_to_class(&detector.check);
        let mut nodes = Vec::new();
        let mut edges = Vec::new();

        let mut label_map: HashMap<String, (String, Uuid)> = HashMap::new();
        let mut counters: HashMap<&str, usize> = HashMap::new();

        // Create the classification node
        let class_node_id = Uuid::new_v4();
        nodes.push(VulnNode {
            id: class_node_id,
            node_type: VulnNodeType::VulnClassification,
            label: format!("{:?}", vuln_class),
            metadata: serde_json::json!({ "check": detector.check }),
        });

        // Track nodes by type for relationship inference
        let mut function_ids = Vec::new();
        let mut variable_ids = Vec::new();
        let mut external_call_ids = Vec::new();

        for element in &detector.elements {
            let prefix = match element.element_type.as_str() {
                "function" => "fn",
                "variable" => "var",
                "contract" => "contract",
                "node" => "call",
                _ => "node",
            };

            let count = counters.entry(prefix).or_insert(0);
            let anonymized_label = format!("{}_{}", prefix, count);
            *count += 1;

            let node_id = Uuid::new_v4();
            let node_type = match element.element_type.as_str() {
                "function" => {
                    function_ids.push(node_id);
                    VulnNodeType::Function
                }
                "variable" => {
                    variable_ids.push(node_id);
                    VulnNodeType::StateVariable
                }
                "node" => {
                    external_call_ids.push(node_id);
                    VulnNodeType::ExternalCall
                }
                _ => VulnNodeType::Function,
            };

            label_map.insert(element.name.clone(), (anonymized_label.clone(), node_id));

            nodes.push(VulnNode {
                id: node_id,
                node_type,
                label: anonymized_label.clone(),
                metadata: serde_json::json!({ "original_type": element.element_type }),
            });

            // Create an edge linking this element to the vuln class
            edges.push(VulnEdge {
                from: node_id,
                to: class_node_id,
                relation: EdgeRelation::ClassifiedAs,
            });
        }

        // Infer additional edges based on vulnerability class
        match vuln_class {
            VulnClass::Reentrancy => {
                // Reentrancy pattern: function -> external call -> function (callback)
                // Typically: fn_0 calls external -> writes to state variable
                if function_ids.len() >= 1 && !variable_ids.is_empty() {
                    for &fn_id in &function_ids {
                        for &var_id in &variable_ids {
                            edges.push(VulnEdge {
                                from: fn_id,
                                to: var_id,
                                relation: EdgeRelation::Writes,
                            });
                        }
                    }
                }
                if !function_ids.is_empty() && !external_call_ids.is_empty() {
                    for &fn_id in &function_ids {
                        for &call_id in &external_call_ids {
                            edges.push(VulnEdge {
                                from: fn_id,
                                to: call_id,
                                relation: EdgeRelation::Calls,
                            });
                        }
                    }
                }
            }
            VulnClass::AccessControl => {
                // Access control issues: function accesses sensitive state without checks
                if !function_ids.is_empty() && !variable_ids.is_empty() {
                    for &fn_id in &function_ids {
                        for &var_id in &variable_ids {
                            edges.push(VulnEdge {
                                from: fn_id,
                                to: var_id,
                                relation: EdgeRelation::Writes,
                            });
                        }
                    }
                }
            }
            VulnClass::UncheckedReturn => {
                // Unchecked return: function makes external call without checking result
                if !function_ids.is_empty() && !external_call_ids.is_empty() {
                    for &fn_id in &function_ids {
                        for &call_id in &external_call_ids {
                            edges.push(VulnEdge {
                                from: fn_id,
                                to: call_id,
                                relation: EdgeRelation::Calls,
                            });
                        }
                    }
                }
            }
            VulnClass::ArithmeticOverflow | VulnClass::TimestampDependence => {
                // Arithmetic/timestamp issues: function reads/writes state variables
                if !function_ids.is_empty() && !variable_ids.is_empty() {
                    for &fn_id in &function_ids {
                        for &var_id in &variable_ids {
                            edges.push(VulnEdge {
                                from: fn_id,
                                to: var_id,
                                relation: EdgeRelation::Reads,
                            });
                        }
                    }
                }
            }
            _ => {
                // Default: create basic call relationships
                if function_ids.len() > 1 {
                    // Create call chain between functions
                    for i in 0..function_ids.len() - 1 {
                        edges.push(VulnEdge {
                            from: function_ids[i],
                            to: function_ids[i + 1],
                            relation: EdgeRelation::Calls,
                        });
                    }
                }
            }
        }

        AbstractPattern {
            vuln_class,
            severity: detector.impact.clone(),
            nodes,
            edges,
        }
    }

    pub(crate) fn map_check_to_class(check: &str) -> VulnClass {
        match check {
            "reentrancy-eth" | "reentrancy-no-eth" | "reentrancy-benign" | "reentrancy-unlimited-gas" | "reentrancy-events" => VulnClass::Reentrancy,
            "arbitrary-send-erc20" | "arbitrary-send-erc20-permit" | "arbitrary-send-eth" | "controlled-delegatecall" | "suicidal" => VulnClass::AccessControl,
            "divide-before-multiply" | "weak-prng" => VulnClass::ArithmeticOverflow,
            "unchecked-lowlevel" | "unchecked-send" | "unchecked-transfer" => VulnClass::UncheckedReturn,
            "tx-origin" => VulnClass::TxOriginAuth,
            "unprotected-upgrade" => VulnClass::UnprotectedSelfDestruct,
            "timestamp" => VulnClass::TimestampDependence,
            "delegatecall-loop" => VulnClass::DelegateCallInjection,
            _ => VulnClass::Other(check.to_string()),
        }
    }
}
