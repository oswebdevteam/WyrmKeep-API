use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum VulnClass {
    Reentrancy,              // SWC-107
    AccessControl,           // SWC-105, SWC-106
    ArithmeticOverflow,      // SWC-101
    UncheckedReturn,         // SWC-104
    TxOriginAuth,            // SWC-115
    UnprotectedSelfDestruct, // SWC-106
    FrontRunning,            // SWC-114
    TimestampDependence,     // SWC-116
    DelegateCallInjection,   // SWC-112
    Other(String),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum VulnNodeType {
    Function,
    StateVariable,
    ExternalCall,
    Invariant,
    VulnClassification,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum EdgeRelation {
    Calls,
    Reads,
    Writes,
    Violates,
    ClassifiedAs,
    SimilarTo,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnNode {
    pub id: Uuid,
    pub node_type: VulnNodeType,
    pub label: String,       // anonymized: "fn_0", "var_1"
    pub metadata: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnEdge {
    pub from: Uuid,
    pub to: Uuid,
    pub relation: EdgeRelation,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AbstractPattern {
    pub vuln_class: VulnClass,
    pub severity: String,
    pub nodes: Vec<VulnNode>,
    pub edges: Vec<VulnEdge>,
}
