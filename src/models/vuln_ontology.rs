use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum VulnClass {
    Reentrancy,
    AccessControl,
    ArithmeticOverflow,
    UncheckedReturn,
    TxOriginAuth,
    UnprotectedSelfDestruct,
    FrontRunning,
    TimestampDependence,
    DelegateCallInjection,
    FlashLoanManipulation,
    PriceOracleManipulation,
    MissingSigner,
    PdaSeedCollision,
    FeltOverflow,
    ValidatorBypass,
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
    pub label: String,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttackStep {
    pub order: u32,
    pub function_name: String,
    pub action: String,
    pub line_range: Option<LineRange>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LineRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CodeDiff {
    pub original: String,
    pub patched: String,
    pub description: String,
}
