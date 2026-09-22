use crate::models::vuln_ontology::VulnClass;

pub struct PatternAbstractor;

impl PatternAbstractor {
    pub fn map_check_to_class(check: &str) -> VulnClass {
        match check {
            "reentrancy-eth" | "reentrancy-no-eth" | "reentrancy-benign" | "reentrancy-unlimited-gas" | "reentrancy-events" => VulnClass::Reentrancy,
            "arbitrary-send-erc20" | "arbitrary-send-erc20-permit" | "arbitrary-send-eth" | "controlled-delegatecall" | "suicidal" => VulnClass::AccessControl,
            "divide-before-multiply" | "weak-prng" => VulnClass::ArithmeticOverflow,
            "unchecked-lowlevel" | "unchecked-send" | "unchecked-transfer" => VulnClass::UncheckedReturn,
            "tx-origin" => VulnClass::TxOriginAuth,
            "unprotected-upgrade" => VulnClass::UnprotectedSelfDestruct,
            "timestamp" => VulnClass::TimestampDependence,
            "delegatecall-loop" => VulnClass::DelegateCallInjection,
            "flash-loan" | "flash-loan-manipulation" => VulnClass::FlashLoanManipulation,
            "price-oracle" | "price-manipulation" => VulnClass::PriceOracleManipulation,
            "missing-signer" | "missing-signer-check" => VulnClass::MissingSigner,
            "pda-seed-collision" => VulnClass::PdaSeedCollision,
            "felt-overflow" => VulnClass::FeltOverflow,
            "validator-bypass" => VulnClass::ValidatorBypass,
            _ => VulnClass::Other(check.to_string()),
        }
    }
}
