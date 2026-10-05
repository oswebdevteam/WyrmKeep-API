use crate::models::contract::ContractLanguage;
use crate::models::finding::FindingSeverity;
use crate::models::vuln_ontology::{LineRange, VulnClass};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FixHint {
    pub patched: String,
    pub explanation: String,
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub check_name: String,
    pub vuln_class: VulnClass,
    pub severity: FindingSeverity,
    pub description: String,
    pub affected_lines: Vec<LineRange>,
    pub affected_functions: Vec<String>,
    pub confidence: f32,
    pub action_hint: Option<String>,
    pub fix_hint: Option<FixHint>,
}

pub trait DetectionRule: Send + Sync {
    fn check_name(&self) -> &str;
    fn detect(&self, source: &str) -> Vec<RuleMatch>;
}

pub fn rules_for(language: &ContractLanguage) -> Vec<Box<dyn DetectionRule>> {
    match language {
        ContractLanguage::Solidity => solidity_rules(),
        ContractLanguage::Rust => rust_solana_rules(),
        ContractLanguage::Move => move_rules(),
        ContractLanguage::Cairo => cairo_rules(),
        ContractLanguage::Aiken => aiken_rules(),
        ContractLanguage::Compact => compact_rules(),
        ContractLanguage::Quorlin => quorlin_rules(),
    }
}

fn solidity_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(ReentrancyRule),
        Box::new(UncheckedReturnRule),
        Box::new(TxOriginRule),
        Box::new(AccessControlRule),
        Box::new(ArithmeticRule),
        Box::new(TimestampRule),
        Box::new(DelegateCallRule),
        Box::new(FlashLoanRule),
        Box::new(PriceOracleRule),
        Box::new(UnprotectedMintRule),
        Box::new(SignatureReplayRule),
        Box::new(SignatureMalleabilityRule),
        Box::new(CrossChainReplayRule),
        Box::new(ERC4626InflationRule),
        Box::new(UnboundedLoopRule),
    ]
}

fn rust_solana_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(MissingSignerRule),
        Box::new(PdaSeedRule),
        Box::new(RustArithmeticRule),
        Box::new(MissingOwnerCheckRule),
        Box::new(UncheckedAccountOwnerRule),
        Box::new(MissingRentExemptRule),
        Box::new(UncheckedAccountTypeRule),
        Box::new(RemainingAccountsRule),
        Box::new(BumpCanonicalRule),
    ]
}

fn move_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(MoveArithmeticRule),
        Box::new(MoveAcquiresRule),
        Box::new(MoveUnprotectedEntryRule),
        Box::new(MoveSharedObjectRule),
        Box::new(MoveAccessControlRule),
        Box::new(MovePublicMutatorRule),
    ]
}

fn cairo_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(FeltOverflowRule),
        Box::new(CairoReentrancyRule),
        Box::new(CairoUnprotectedWriteRule),
        Box::new(CairoMissingEventRule),
        Box::new(CairoUpgradeRule),
        Box::new(CairoUnsafeUnwrapRule),
    ]
}

fn aiken_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(ValidatorBypassRule),
        Box::new(AikenDatumHijackRule),
        Box::new(AikenDoubleSatisfactionRule),
        Box::new(AikenMintBoundaryRule),
        Box::new(AikenMissingSignatoryRule),
        Box::new(AikenTimeRangeRule),
    ]
}

fn compact_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(CompactStateLeakRule),
        Box::new(CompactPrivateLeakRule),
        Box::new(CompactWitnessLogRule),
        Box::new(CompactUnderConstrainedRule),
    ]
}

fn quorlin_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(QuorlinPermissionRule),
        Box::new(QuorlinUnrestrictedWriteRule),
        Box::new(QuorlinPrivilegedWriteRule),
        Box::new(QuorlinOwnershipTransferRule),
        Box::new(QuorlinOriginAuthRule),
        Box::new(QuorlinNobodyCheckRule),
        Box::new(QuorlinAmountZeroRule),
        Box::new(QuorlinCeiViolationRule),
        Box::new(QuorlinUncheckedCallRule),
        Box::new(QuorlinEventMissingRule),
        Box::new(QuorlinWrappingMathRule),
    ]
}

struct ReentrancyRule;

impl DetectionRule for ReentrancyRule {
    fn check_name(&self) -> &str { "reentrancy-eth" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (fn_start, fn_name) in find_functions(&lines) {
            let fn_body = extract_function_body(&lines, fn_start);

            let has_external_call = fn_body.iter().any(|(_, l)| {
                l.contains(".call{") || l.contains(".call(") ||
                l.contains(".send(") || l.contains(".transfer(")
            });
            let external_call_line = fn_body.iter().find(|(_, l)| {
                l.contains(".call{") || l.contains(".call(") ||
                l.contains(".send(") || l.contains(".transfer(")
            });

            if !has_external_call {
                continue;
            }

            let call_idx = fn_body.iter().position(|(_, l)| {
                l.contains(".call{") || l.contains(".call(") ||
                l.contains(".send(") || l.contains(".transfer(")
            });

            if let Some(ci) = call_idx {
                let has_state_write_after = fn_body[ci..].iter().any(|(_, l)| {
                    (l.contains('=') && !l.contains("==") && !l.contains("!=") &&
                     !l.contains(">=") && !l.contains("<=")) ||
                    l.contains("-=") || l.contains("+=") ||
                    l.contains("delete ")
                });

                if has_state_write_after {
                    let call_line = external_call_line.map(|(n, _)| *n as u32).unwrap_or(fn_start as u32);
                    let description = format!(
                        "Potential reentrancy in `{fn_name}`: external call precedes state modification. \
                         An attacker can re-enter this function before state is updated."
                    );
                    let patched = format!(
                        "// Move state changes before the external call in `{fn_name}`\n\
                         // Or use the Checks-Effects-Interactions pattern\n\
                         // Or add a ReentrancyGuard modifier"
                    );
                    matches.push(RuleMatch {
                        check_name: self.check_name().into(),
                        vuln_class: VulnClass::Reentrancy,
                        severity: FindingSeverity::High,
                        description,
                        affected_lines: vec![LineRange {
                            start: fn_start as u32 + 1,
                            end: call_line + 1,
                        }],
                        affected_functions: vec![fn_name],
                        confidence: 0.85,
                        action_hint: Some("external_call".into()),
                        fix_hint: Some(FixHint {
                            patched,
                            explanation: "Apply Checks-Effects-Interactions: update state before making external calls.".into(),
                        }),
                    });
                }
            }
        }

        matches
    }
}

struct UncheckedReturnRule;

impl DetectionRule for UncheckedReturnRule {
    fn check_name(&self) -> &str { "unchecked-return" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (fn_start, fn_name) in find_functions(&lines) {
            let fn_body = extract_function_body(&lines, fn_start);

            for (line_no, line) in &fn_body {
                let has_low_level = line.contains(".call(") ||
                    line.contains(".delegatecall(") ||
                    line.contains(".staticcall(");

                if !has_low_level { continue; }

                let is_checked = line.contains("require(") ||
                    line.contains("(bool success") ||
                    line.contains("(bool ok") ||
                    line.trim().starts_with("require") ||
                    line.contains("if (!");

                if is_checked { continue; }

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::UncheckedReturn,
                    severity: FindingSeverity::Medium,
                    description: format!(
                        "Unchecked return value from low-level call in `{fn_name}`. \
                         The call may silently fail."
                    ),
                    affected_lines: vec![LineRange {
                        start: *line_no as u32 + 1,
                        end: *line_no as u32 + 1,
                    }],
                    affected_functions: vec![fn_name.clone()],
                    confidence: 0.80,
                    action_hint: Some("call".into()),
                    fix_hint: Some(FixHint {
                        patched: "(bool success, ) = target.call(data);\nrequire(success, \"Call failed\");".into(),
                        explanation: "Capture and check the boolean return value of low-level calls.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct TxOriginRule;

impl DetectionRule for TxOriginRule {
    fn check_name(&self) -> &str { "tx-origin" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("tx.origin") { continue; }

            let in_condition = line.contains("require(") ||
                line.contains("if (") || line.contains("if(") ||
                line.contains("assert(");

            if !in_condition { continue; }

            let fn_name = find_enclosing_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::TxOriginAuth,
                severity: FindingSeverity::High,
                description: format!(
                    "Use of `tx.origin` for authorization in `{}`. \
                     A phishing contract can relay calls and pass the tx.origin check.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.95,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "require(msg.sender == owner, \"Not authorized\");".into(),
                    explanation: "Replace tx.origin with msg.sender for authorization checks.".into(),
                }),
            });
        }

        matches
    }
}

struct AccessControlRule;

impl DetectionRule for AccessControlRule {
    fn check_name(&self) -> &str { "access-control" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let dangerous_ops = ["selfdestruct(", "suicide(", "delegatecall("];

        for (fn_start, fn_name) in find_functions(&lines) {
            let fn_header = lines.get(fn_start).copied().unwrap_or("");
            let has_modifier = fn_header.contains("onlyOwner") ||
                fn_header.contains("onlyAdmin") ||
                fn_header.contains("auth") ||
                fn_header.contains("restricted");

            if has_modifier { continue; }

            let fn_body = extract_function_body(&lines, fn_start);
            let has_require_sender = fn_body.iter().any(|(_, l)| {
                l.contains("msg.sender") && (l.contains("require(") || l.contains("if ("))
            });

            if has_require_sender { continue; }

            for (line_no, line) in &fn_body {
                for op in &dangerous_ops {
                    if line.contains(op) {
                        let op_name = op.trim_end_matches('(');
                        let description = format!(
                            "Dangerous operation `{op_name}` in `{fn_name}` without access control. \
                             Any address can call this function."
                        );
                        let patched = format!(
                            "modifier onlyOwner() {{\n    require(msg.sender == owner);\n    _;\n}}\n\nfunction {fn_name}(...) public onlyOwner {{"
                        );
                        matches.push(RuleMatch {
                            check_name: self.check_name().into(),
                            vuln_class: VulnClass::AccessControl,
                            severity: FindingSeverity::High,
                            description,
                            affected_lines: vec![LineRange {
                                start: *line_no as u32 + 1,
                                end: *line_no as u32 + 1,
                            }],
                            affected_functions: vec![fn_name.clone()],
                            confidence: 0.90,
                            action_hint: Some("write_state".into()),
                            fix_hint: Some(FixHint {
                                patched,
                                explanation: "Add an access control modifier to restrict who can call this function.".into(),
                            }),
                        });
                    }
                }
            }
        }

        matches
    }
}

struct ArithmeticRule;

impl DetectionRule for ArithmeticRule {
    fn check_name(&self) -> &str { "arithmetic-overflow" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();

        let pre_08 = source.contains("pragma solidity ^0.7") ||
            source.contains("pragma solidity ^0.6") ||
            source.contains("pragma solidity ^0.5") ||
            source.contains("pragma solidity ^0.4");

        if !pre_08 { return matches; }

        let has_safemath = source.contains("using SafeMath");

        if has_safemath { return matches; }

        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let has_arithmetic = (line.contains('+') || line.contains('*') ||
                line.contains("**")) && line.contains('=');
            let in_unchecked = line.contains("unchecked");

            if has_arithmetic && !in_unchecked {
                let fn_name = find_enclosing_function(&lines, i)
                    .unwrap_or_else(|| "<unknown>".into());

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::ArithmeticOverflow,
                    severity: FindingSeverity::Medium,
                    description: format!(
                        "Potential arithmetic overflow in `{}` (pre-0.8.0 without SafeMath).",
                        fn_name
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: i as u32 + 1,
                    }],
                    affected_functions: vec![fn_name],
                    confidence: 0.70,
                    action_hint: Some("write_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "using SafeMath for uint256;".into(),
                        explanation: "Use SafeMath library or upgrade to Solidity ≥0.8.0 for built-in overflow checks.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct TimestampRule;

impl DetectionRule for TimestampRule {
    fn check_name(&self) -> &str { "timestamp-dependence" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let uses_timestamp = line.contains("block.timestamp") || line.contains("now");
            let in_condition = line.contains("if") || line.contains("require") ||
                line.contains("assert") || line.contains("==") || line.contains("<=");

            if uses_timestamp && in_condition {
                let fn_name = find_enclosing_function(&lines, i)
                    .unwrap_or_else(|| "<unknown>".into());

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::TimestampDependence,
                    severity: FindingSeverity::Low,
                    description: format!(
                        "Block timestamp used in critical comparison in `{}`. \
                         Miners can manipulate timestamps by ~15 seconds.",
                        fn_name
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: i as u32 + 1,
                    }],
                    affected_functions: vec![fn_name],
                    confidence: 0.65,
                    action_hint: Some("read_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Use block.number instead of block.timestamp for time-sensitive logic".into(),
                        explanation: "Avoid relying on block.timestamp for critical logic; miners have limited control over it.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct DelegateCallRule;

impl DetectionRule for DelegateCallRule {
    fn check_name(&self) -> &str { "delegatecall-injection" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (fn_start, fn_name) in find_functions(&lines) {
            let fn_body = extract_function_body(&lines, fn_start);

            for (line_no, line) in &fn_body {
                if !line.contains(".delegatecall(") { continue; }

                let fn_header = lines.get(fn_start).copied().unwrap_or("");
                let has_protection = fn_header.contains("onlyOwner") ||
                    fn_header.contains("internal") ||
                    fn_header.contains("private");

                if has_protection { continue; }

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::DelegateCallInjection,
                    severity: FindingSeverity::High,
                    description: format!(
                        "Unprotected `delegatecall` in public function `{fn_name}`. \
                         An attacker could execute arbitrary code in this contract's context."
                    ),
                    affected_lines: vec![LineRange {
                        start: *line_no as u32 + 1,
                        end: *line_no as u32 + 1,
                    }],
                    affected_functions: vec![fn_name.clone()],
                    confidence: 0.88,
                    action_hint: Some("external_call".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Restrict delegatecall to trusted implementation addresses only\n// Add onlyOwner or similar modifier".into(),
                        explanation: "Restrict delegatecall targets and add access control.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct FlashLoanRule;

impl DetectionRule for FlashLoanRule {
    fn check_name(&self) -> &str { "flash-loan-manipulation" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let flash_loan_indicators = [
            "flashLoan(", "flashBorrow(", "executeOperation(",
            "onFlashLoan(", "IERC3156",
        ];

        let price_reads = [
            "getReserves()", "balanceOf(", "getAmountOut(",
            "latestAnswer()", "slot0(",
        ];

        let has_flash_loan = lines.iter().any(|l| {
            flash_loan_indicators.iter().any(|ind| l.contains(ind))
        });

        if !has_flash_loan { return matches; }

        for (i, line) in lines.iter().enumerate() {
            let reads_price = price_reads.iter().any(|p| line.contains(p));
            if !reads_price { continue; }

            let fn_name = find_enclosing_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::FlashLoanManipulation,
                severity: FindingSeverity::High,
                description: format!(
                    "Price/reserve read in `{}` within a flash-loan-aware contract. \
                     Flash loans can temporarily manipulate these values.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.75,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// Use a TWAP oracle or Chainlink price feed instead of spot prices".into(),
                    explanation: "Spot prices from DEX reserves can be manipulated via flash loans. Use time-weighted average prices.".into(),
                }),
            });
        }

        matches
    }
}

struct PriceOracleRule;

impl DetectionRule for PriceOracleRule {
    fn check_name(&self) -> &str { "price-oracle-manipulation" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let spot_price_patterns = [
            "getReserves()", "balanceOf(address(this))",
            "token0.balanceOf(", "token1.balanceOf(",
        ];

        for (i, line) in lines.iter().enumerate() {
            let uses_spot = spot_price_patterns.iter().any(|p| line.contains(p));
            if !uses_spot { continue; }

            let nearby_has_swap = lines[i.saturating_sub(5)..lines.len().min(i + 10)]
                .iter()
                .any(|l| l.contains("swap(") || l.contains("mint(") || l.contains("burn("));

            if !nearby_has_swap { continue; }

            let fn_name = find_enclosing_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::PriceOracleManipulation,
                severity: FindingSeverity::High,
                description: format!(
                    "Spot price from reserves used near swap/mint/burn in `{}`. \
                     This is vulnerable to sandwich attacks.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.72,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// Use Chainlink or a TWAP oracle for price data\n// Do not derive prices from current pool reserves".into(),
                    explanation: "On-chain reserve ratios are manipulable within a single transaction. Use external oracles.".into(),
                }),
            });
        }

        matches
    }
}

struct UnprotectedMintRule;

impl DetectionRule for UnprotectedMintRule {
    fn check_name(&self) -> &str { "unprotected-mint" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (fn_start, fn_name) in find_functions(&lines) {
            let lower = fn_name.to_lowercase();
            let is_mint = lower.contains("mint") || lower.contains("burn");
            if !is_mint { continue; }

            let header = lines.get(fn_start).copied().unwrap_or("");
            let is_public = header.contains("public") || header.contains("external");
            if !is_public { continue; }

            let has_auth = header.contains("onlyOwner") || header.contains("onlyRole") ||
                header.contains("onlyAdmin") || header.contains("auth") ||
                header.contains("restricted") || header.contains("requiresAuth");

            if has_auth { continue; }

            let fn_body = extract_function_body(&lines, fn_start);
            let has_sender_check = fn_body.iter().any(|(_, l)| {
                l.contains("msg.sender") && (l.contains("require(") || l.contains("if ("))
            });

            if has_sender_check { continue; }

            let description = format!(
                "Public token mint/burn function `{fn_name}` without access control. \
                 Anyone can create or destroy tokens."
            );
            let patched = format!(
                "function {fn_name}(...) public onlyRole(MINTER_ROLE) {{ ... }}"
            );
            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::AccessControl,
                severity: FindingSeverity::High,
                description,
                affected_lines: vec![LineRange {
                    start: fn_start as u32 + 1,
                    end: fn_start as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.85,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched,
                    explanation: "Restrict mint/burn to an authorized role or owner using an access control modifier.".into(),
                }),
            });
        }

        matches
    }
}

struct SignatureReplayRule;

impl DetectionRule for SignatureReplayRule {
    fn check_name(&self) -> &str { "signature-replay" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_recover = lines.iter().any(|l| {
            l.contains("ecrecover(") || l.contains("ECDSA.recover(") ||
            l.contains("SignatureChecker.isValidSignatureNow(")
        });

        if !has_recover { return matches; }

        let uses_nonce = source.contains("nonce");
        let uses_deadline = source.contains("deadline") || source.contains("expiry") ||
            source.contains("validUntil") || source.contains("expiration");

        if uses_nonce && uses_deadline { return matches; }

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("ecrecover(") && !line.contains("ECDSA.recover(") { continue; }

            let fn_name = find_enclosing_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            let missing = match (uses_nonce, uses_deadline) {
                (false, false) => "nonce or expiry/deadline",
                (false, true) => "nonce",
                (true, false) => "expiry/deadline",
                (true, true) => return matches,
            };

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("SignatureReplay".into()),
                severity: FindingSeverity::High,
                description: format!(
                    "Signature recovered in `{}` without a {}. \
                     A captured signature can be replayed by an attacker.",
                    fn_name, missing
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.78,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// Include a per-user nonce and a deadline in the signed payload\n\
                              // Verify: require(block.timestamp <= deadline, \"expired\");\n\
                              // Mark nonce consumed after use".into(),
                    explanation: "Bind each signature to a nonce and a deadline so it cannot be replayed.".into(),
                }),
            });
        }

        matches
    }
}

struct SignatureMalleabilityRule;

impl DetectionRule for SignatureMalleabilityRule {
    fn check_name(&self) -> &str { "signature-malleability" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_raw_ecrecover = lines.iter().any(|l| l.contains("ecrecover("));
        if !has_raw_ecrecover { return matches; }

        // EIP-2 / EIP-2098 malleability guard: upper-bound the s value
        let has_s_check = source.contains("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")
            || source.contains("secp256k1n") || source.contains("HALF_N")
            || source.contains("splitSignature") || source.contains("ECDSA.recover");

        if has_s_check { return matches; }

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("ecrecover(") { continue; }

            let fn_name = find_enclosing_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("SignatureMalleability".into()),
                severity: FindingSeverity::Medium,
                description: format!(
                    "Raw `ecrecover` in `{}` without checking that `s` is in the lower \
                     half of the curve order. Both (r, s) and (r, n-s) are valid signatures, \
                     enabling signature malleability (EIP-2).",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.70,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// Use OpenZeppelin ECDSA.recover, or enforce:\n\
                              // require(uint256(s) <= 0x7FFF...20A0, \"invalid s\");\n\
                              // require(v == 27 || v == 28, \"invalid v\");".into(),
                    explanation: "Bound `s` to the lower half of the curve order to prevent malleable signature pairs.".into(),
                }),
            });
        }

        matches
    }
}

struct CrossChainReplayRule;

impl DetectionRule for CrossChainReplayRule {
    fn check_name(&self) -> &str { "cross-chain-replay" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_eip712 = source.contains("EIP712Domain") || source.contains("DOMAIN_SEPARATOR")
            || source.contains("domainSeparator") || source.contains("_typedDataHash");

        if !has_eip712 { return matches; }

        let binds_chain_id = source.contains("block.chainid") || source.contains("chainId");

        if binds_chain_id { return matches; }

        for (i, line) in lines.iter().enumerate() {
            let is_domain = line.contains("EIP712Domain") ||
                line.contains("DOMAIN_SEPARATOR") || line.contains("domainSeparator");
            if !is_domain { continue; }

            let fn_name = find_enclosing_function(&lines, i)
                .unwrap_or_else(|| "<constructor>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("CrossChainReplay".into()),
                severity: FindingSeverity::High,
                description: format!(
                    "EIP-712 domain separator constructed without binding `chainId` (in `{}`). \
                     A signature valid on one chain is valid on every fork/chain where this \
                     contract exists at the same address.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.75,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "bytes32 domainSeparator = keccak256(abi.encode(\n\
                              \x20   keccak256(\"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)\"),\n\
                              \x20   keccak256(bytes(name)), keccak256(bytes(version)),\n\
                              \x20   block.chainid, address(this)\n\
                              ));".into(),
                    explanation: "Include block.chainid in the EIP-712 domain so signatures are chain-specific.".into(),
                }),
            });
        }

        matches
    }
}

struct ERC4626InflationRule;

impl DetectionRule for ERC4626InflationRule {
    fn check_name(&self) -> &str { "erc4626-share-inflation" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let is_vault = source.contains("IERC4626") || source.contains("convertToShares") ||
            source.contains("convertToAssets") || (source.contains("totalAssets") &&
                source.contains("totalSupply"));

        if !is_vault { return matches; }

        // Defenses against the first-depositor / donation attack
        let has_guard = source.contains("deadShares") || source.contains("dead shares") ||
            source.contains("_decimalsOffset") || source.contains("virtual") ||
            source.contains("totalSupply() == 0") || source.contains("totalSupply()==0") ||
            source.contains("MINIMUM_LIQUIDITY");

        if has_guard { return matches; }

        for (i, line) in lines.iter().enumerate() {
            let is_deposit = line.contains("function deposit(") ||
                line.contains("function mint(") || line.contains("function withdraw(") ||
                line.contains("function redeem(");
            if !is_deposit { continue; }

            let fn_name = find_enclosing_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("ShareInflation".into()),
                severity: FindingSeverity::High,
                description: format!(
                    "ERC-4626 vault entry point `{}` found without first-depositor inflation \
                     protection. An attacker can donate assets directly to the vault to skew the \
                     share price and steal subsequent deposits.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.65,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// Offset decimals (virtual shares/assets, OZ style):\n\
                              // ERC4626(name, symbol, IERC20(asset), _decimalsOffset())\n\
                              // Or seed the vault with MINIMUM_LIQUIDITY on first deposit".into(),
                    explanation: "Use virtual share/assets offset or dead shares so a single donation cannot manipulate the exchange rate.".into(),
                }),
            });
        }

        matches
    }
}

struct UnboundedLoopRule;

impl DetectionRule for UnboundedLoopRule {
    fn check_name(&self) -> &str { "unbounded-loop-dos" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (fn_start, fn_name) in find_functions(&lines) {
            let fn_body = extract_function_body(&lines, fn_start);

            for (idx, (line_no, line)) in fn_body.iter().enumerate() {
                let is_loop = line.contains("for (") || line.contains("for(") ||
                    line.contains("while (") || line.contains("while(");
                if !is_loop { continue; }

                let iterates_dynamic = line.contains(".length") || line.contains(".count()") ||
                    line.contains(".totalSupply");

                if !iterates_dynamic { continue; }

                let window = &fn_body[idx..fn_body.len().min(idx + 25)];
                let has_external_call = window.iter().any(|(_, l)| {
                    l.contains(".call(") || l.contains(".transfer(") ||
                    l.contains(".send(") || l.contains(".delegatecall(")
                });

                if !has_external_call { continue; }

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::Other("DenialOfService".into()),
                    severity: FindingSeverity::Medium,
                    description: format!(
                        "Unbounded loop over a dynamic collection in `{fn_name}` containing an \
                         external call. If the collection grows, the transaction can exceed \
                         the block gas limit, bricking the function."
                    ),
                    affected_lines: vec![LineRange {
                        start: *line_no as u32 + 1,
                        end: *line_no as u32 + 1,
                    }],
                    affected_functions: vec![fn_name.clone()],
                    confidence: 0.68,
                    action_hint: Some("external_call".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Batch processing with pagination:\n\
                                  // function distribute(uint start, uint count) external {\n\
                                  //     uint end = Math.min(start + count, recipients.length);\n\
                                  //     for (uint i = start; i < end; i++) { ... }\n\
                                  // }".into(),
                        explanation: "Bound loop iterations per transaction and allow callers to paginate through the collection.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct MissingSignerRule;

impl DetectionRule for MissingSignerRule {
    fn check_name(&self) -> &str { "missing-signer-check" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut in_accounts_struct = false;
        let mut struct_name = String::new();

        for (i, line) in lines.iter().enumerate() {
            if line.contains("#[derive(Accounts)]") {
                in_accounts_struct = true;
                continue;
            }

            if in_accounts_struct && line.contains("pub struct") {
                struct_name = line.split_whitespace()
                    .nth(2)
                    .unwrap_or("<unknown>")
                    .trim_end_matches('<')
                    .into();
                continue;
            }

            if in_accounts_struct && line.trim() == "}" {
                in_accounts_struct = false;
                continue;
            }

            if in_accounts_struct && line.contains("AccountInfo") {
                let has_signer = lines[i.saturating_sub(3)..=i]
                    .iter()
                    .any(|l| l.contains("Signer") || l.contains("#[account(signer)]")
                        || l.contains("is_signer"));

                if !has_signer {
                    let field_name = line.split(':')
                        .next()
                        .map(|s| s.trim().trim_start_matches("pub "))
                        .unwrap_or("<field>");

                    matches.push(RuleMatch {
                        check_name: self.check_name().into(),
                        vuln_class: VulnClass::MissingSigner,
                        severity: FindingSeverity::High,
                        description: format!(
                            "Account `{}` in `{}` is not validated as a signer. \
                             Any account can be passed for this field.",
                            field_name, struct_name
                        ),
                        affected_lines: vec![LineRange {
                            start: i as u32 + 1,
                            end: i as u32 + 1,
                        }],
                        affected_functions: vec![struct_name.clone()],
                        confidence: 0.82,
                        action_hint: Some("read_state".into()),
                        fix_hint: Some(FixHint {
                            patched: format!("#[account(signer)]\npub {}: Signer<'info>,", field_name),
                            explanation: "Use the Signer type or #[account(signer)] constraint to enforce signature verification.".into(),
                        }),
                    });
                }
            }
        }

        matches
    }
}

struct PdaSeedRule;

impl DetectionRule for PdaSeedRule {
    fn check_name(&self) -> &str { "pda-seed-collision" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("find_program_address") && !line.contains("create_program_address") {
                continue;
            }

            let has_unique_seed = lines[i.saturating_sub(3)..=i].iter().any(|l| {
                l.contains("key()") || l.contains(".key.as_ref()") || l.contains("user.key()")
            });

            if has_unique_seed { continue; }

            let fn_name = find_rust_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::PdaSeedCollision,
                severity: FindingSeverity::Medium,
                description: format!(
                    "PDA derivation in `{}` may not include a unique seed (e.g., user pubkey). \
                     Multiple users could map to the same PDA.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.68,
                action_hint: Some("call".into()),
                fix_hint: Some(FixHint {
                    patched: "// Include user pubkey or other unique identifier in PDA seeds\nlet (pda, bump) = Pubkey::find_program_address(\n    &[b\"prefix\", user.key().as_ref()],\n    program_id,\n);".into(),
                    explanation: "Include a user-specific seed component to prevent PDA collisions across users.".into(),
                }),
            });
        }

        matches
    }
}

struct RustArithmeticRule;

impl DetectionRule for RustArithmeticRule {
    fn check_name(&self) -> &str { "rust-arithmetic-overflow" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let has_unchecked_math = (line.contains(" + ") || line.contains(" * ") ||
                line.contains(" - ")) &&
                !line.contains("checked_") && !line.contains("saturating_") &&
                !line.contains("wrapping_") && !line.contains("//");

            let involves_amounts = line.contains("amount") || line.contains("balance") ||
                line.contains("supply") || line.contains("lamports");

            if has_unchecked_math && involves_amounts {
                let fn_name = find_rust_function(&lines, i)
                    .unwrap_or_else(|| "<unknown>".into());

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::ArithmeticOverflow,
                    severity: FindingSeverity::Medium,
                    description: format!(
                        "Unchecked arithmetic on financial value in `{}`. \
                         In release builds, Rust wraps on overflow.",
                        fn_name
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: i as u32 + 1,
                    }],
                    affected_functions: vec![fn_name],
                    confidence: 0.65,
                    action_hint: Some("write_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "let result = a.checked_add(b).ok_or(ErrorCode::Overflow)?;".into(),
                        explanation: "Use checked_add/checked_sub/checked_mul to handle overflow explicitly.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct MissingOwnerCheckRule;

impl DetectionRule for MissingOwnerCheckRule {
    fn check_name(&self) -> &str { "missing-owner-check" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("Account<") && !line.contains("AccountInfo<") {
                continue;
            }
            if !line.contains("mut") { continue; }

            let has_owner_check = lines[i.saturating_sub(5)..lines.len().min(i + 3)]
                .iter()
                .any(|l| l.contains("has_one") || l.contains("owner =") ||
                    l.contains("constraint = ") || l.contains(".owner =="));

            if !has_owner_check {
                let field_name = line.split(':')
                    .next()
                    .map(|s| s.trim().trim_start_matches("pub "))
                    .unwrap_or("<field>");

                let fn_name = find_rust_function(&lines, i)
                    .unwrap_or_else(|| "<accounts_struct>".into());

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::AccessControl,
                    severity: FindingSeverity::Medium,
                    description: format!(
                        "Mutable account `{}` without owner validation. \
                         An attacker could pass an account owned by a different program.",
                        field_name
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: i as u32 + 1,
                    }],
                    affected_functions: vec![fn_name],
                    confidence: 0.70,
                    action_hint: Some("write_state".into()),
                    fix_hint: Some(FixHint {
                        patched: format!("#[account(mut, has_one = authority)]\npub {}: Account<'info, MyData>,", field_name),
                        explanation: "Add a has_one or owner constraint to verify account ownership.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct UncheckedAccountOwnerRule;

impl DetectionRule for UncheckedAccountOwnerRule {
    fn check_name(&self) -> &str { "unchecked-account-owner" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_deserialize = lines.iter().any(|l| {
            l.contains("try_from_slice") || l.contains("deserialize(") ||
            l.contains("unpack_from_slice") || l.contains("BorshDeserialize")
        });

        if !has_deserialize { return matches; }

        let has_owner_constraints = source.contains("owner = ") ||
            source.contains("owner=") || source.contains("constraint = account.owner");

        for (i, line) in lines.iter().enumerate() {
            let deserializes = line.contains("try_from_slice") ||
                line.contains(".deserialize(") || line.contains("unpack_from_slice");
            if !deserializes { continue; }

            let window_start = i.saturating_sub(10);
            let has_owner_check = lines[window_start..=i].iter().any(|l| {
                l.contains(".owner ==") || l.contains(".owner !=") ||
                l.contains("owner == program_id") || l.contains("check_owner") ||
                l.contains("assert_eq!(account.owner")
            });

            if has_owner_check { continue; }

            let in_anchor_accounts = has_owner_constraints && lines[..=i].iter().rev().take(30)
                .any(|l| l.contains("#[account(") || l.contains("Account<") ||
                    l.contains("AccountInfo<") || l.contains("UncheckedAccount"));

            if in_anchor_accounts { continue; }

            let fn_name = find_rust_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("UncheckedAccountOwnership".into()),
                severity: FindingSeverity::High,
                description: format!(
                    "Account data deserialized in `{}` without verifying `account.owner`. \
                     An attacker can pass an account owned by a different program containing \
                     attacker-controlled bytes (type cosplay).",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.76,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "assert_eq!(\n\
                              \x20   account.owner,\n\
                              \x20   &crate::id(),\n\
                              \x20   \"account must be owned by this program\"\n\
                              );\n\
                              let data = MyAccount::try_from_slice(&account.data.borrow())?;".into(),
                    explanation: "Always assert account.owner == program_id before deserializing account data.".into(),
                }),
            });
        }

        matches
    }
}

struct MissingRentExemptRule;

impl DetectionRule for MissingRentExemptRule {
    fn check_name(&self) -> &str { "missing-rent-exemption" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let creates_account = lines.iter().any(|l| {
            l.contains("create_account(") || l.contains("create_account_with_seed(")
        });

        if !creates_account { return matches; }

        let handles_rent = source.contains("is_exempt") || source.contains("minimum_balance") ||
            source.contains("RENT_EXEMPT") || source.contains("rent.to_lamports");

        if handles_rent { return matches; }

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("create_account(") && !line.contains("create_account_with_seed(") {
                continue;
            }

            let fn_name = find_rust_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("MissingRentExemption".into()),
                severity: FindingSeverity::Medium,
                description: format!(
                    "Account created in `{}` without rent-exemption handling. \
                     Non-exempt accounts are garbage-collected by the runtime, \
                     silently destroying stored state.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.70,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched: "let rent = Rent::get()?;\n\
                              let lamports = rent.minimum_balance(data_len);\n\
                              assert!(rent.is_exempt(lamports, data_len), \"not rent exempt\");".into(),
                    explanation: "Fund new accounts with rent.minimum_balance(data_len) so they persist.".into(),
                }),
            });
        }

        matches
    }
}

struct UncheckedAccountTypeRule;

impl DetectionRule for UncheckedAccountTypeRule {
    fn check_name(&self) -> &str { "unchecked-account-type" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut in_accounts_struct = false;

        for (i, line) in lines.iter().enumerate() {
            if line.contains("#[derive(Accounts)]") {
                in_accounts_struct = true;
                continue;
            }

            if in_accounts_struct && line.trim() == "}" {
                in_accounts_struct = false;
                continue;
            }

            if !in_accounts_struct { continue; }
            if !line.contains("UncheckedAccount") && !line.contains("AccountInfo") { continue; }
            if line.contains("///") || line.trim().starts_with("//") { continue; }

            let window_start = i.saturating_sub(4);
            let has_constraint = lines[window_start..=i].iter().any(|l| {
                l.contains("constraint") || l.contains("address =") ||
                l.contains("owner =") || l.contains("executable") ||
                l.contains("seeds =") || l.contains("mut,") ||
                l.contains("#[account(init")
            });

            if has_constraint { continue; }

            let field_name = line.split(':')
                .next()
                .map(|s| s.trim().trim_start_matches("pub ").trim_start_matches('#'))
                .unwrap_or("<field>");

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("UninitializedAccount".into()),
                severity: FindingSeverity::High,
                description: format!(
                    "Account field `{}` declared as UncheckedAccount/AccountInfo without any \
                     validation constraint. Any account — wrong program, wrong owner, or \
                     attacker-crafted — can be passed here.",
                    field_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec!["<accounts_struct>".into()],
                confidence: 0.74,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: format!(
                        "#[account(mut, seeds = [b\"{}\", authority.key().as_ref()], bump)]\npub {}: Account<'info, MyData>,",
                        "seed", field_name
                    ),
                    explanation: "Constrain the account with type, owner, address, or PDA seeds so arbitrary accounts cannot be substituted.".into(),
                }),
            });
        }

        matches
    }
}

struct RemainingAccountsRule;

impl DetectionRule for RemainingAccountsRule {
    fn check_name(&self) -> &str { "unvalidated-remaining-accounts" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("remaining_accounts") { continue; }
            if line.trim().starts_with("//") { continue; }

            let fn_name = find_rust_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            let window_end = lines.len().min(i + 30);
            let has_validation = lines[i..window_end].iter().any(|l| {
                l.contains(".owner ==") || l.contains("check_owner") ||
                l.contains("owner != &") || l.contains("key() ==") ||
                l.contains("constraint") || l.contains("verify_account")
            });

            if has_validation { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("UncheckedRemainingAccounts".into()),
                severity: FindingSeverity::High,
                description: format!(
                    "`remaining_accounts` consumed in `{fn_name}` without per-account validation. \
                     The caller can inject arbitrary accounts (wrong owner, wrong program) \
                     into the instruction."
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.72,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "for account in ctx.remaining_accounts {\n\
                              \x20   assert_eq!(account.owner, &crate::id(), \"invalid owner\");\n\
                              \x20   assert!(account.is_writable, \"must be writable\");\n\
                              }".into(),
                    explanation: "Validate owner and role of every remaining account before trusting it.".into(),
                }),
            });
        }

        matches
    }
}

struct BumpCanonicalRule;

impl DetectionRule for BumpCanonicalRule {
    fn check_name(&self) -> &str { "non-canonical-bump" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let has_seeds = line.contains("seeds = [") || line.contains("seeds=[");
            if !has_seeds { continue; }

            let window_end = lines.len().min(i + 4);
            let has_bump = lines[i..window_end].iter().any(|l| l.contains("bump"));

            if has_bump { continue; }

            let field_name = lines[..=i].iter().rev()
                .find(|l| l.contains("pub ") && l.contains(':'))
                .and_then(|l| l.split(':').next())
                .map(|s| s.trim().trim_start_matches("pub ").to_string())
                .unwrap_or_else(|| "<field>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::PdaSeedCollision,
                severity: FindingSeverity::Medium,
                description: format!(
                    "PDA constraint on `{}` declares `seeds` without `bump`. \
                     Without a canonical bump the program accepts non-canonical bumps, \
                     enabling alternate derivation paths for the same seeds.",
                    field_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec!["<accounts_struct>".into()],
                confidence: 0.72,
                action_hint: Some("call".into()),
                fix_hint: Some(FixHint {
                    patched: format!(
                        "#[account(seeds = [b\"vault\", authority.key().as_ref()], bump)]\npub {}: Account<'info, Vault>,",
                        field_name
                    ),
                    explanation: "Always include `bump` (without a value) so Anchor enforces the canonical bump seed.".into(),
                }),
            });
        }

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("create_program_address(") { continue; }

            let window_start = i.saturating_sub(5);
            let verifies_canonical = lines[window_start..=i].iter().any(|l| {
                l.contains("find_program_address(") || l.contains("bump ==") ||
                l.contains("assert_eq!(bump")
            });

            if verifies_canonical { continue; }

            let fn_name = find_rust_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::PdaSeedCollision,
                severity: FindingSeverity::Medium,
                description: format!(
                    "`create_program_address` in `{}` with a caller-provided bump that is \
                     never validated as canonical.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.65,
                action_hint: Some("call".into()),
                fix_hint: Some(FixHint {
                    patched: "let (_, expected_bump) = Pubkey::find_program_address(&seeds, &program_id);\n\
                              assert_eq!(bump, expected_bump, \"non-canonical bump\");".into(),
                    explanation: "Derive the canonical bump yourself and compare, or use find_program_address exclusively.".into(),
                }),
            });
        }

        matches
    }
}

struct MoveArithmeticRule;

impl DetectionRule for MoveArithmeticRule {
    fn check_name(&self) -> &str { "move-arithmetic" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let has_division = line.contains(" / ");
            let has_multiplication_nearby = lines[i.saturating_sub(2)..lines.len().min(i + 3)]
                .iter()
                .any(|l| l.contains(" * "));

            if has_division && has_multiplication_nearby {
                let fn_name = find_move_function(&lines, i)
                    .unwrap_or_else(|| "<unknown>".into());

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::ArithmeticOverflow,
                    severity: FindingSeverity::Medium,
                    description: format!(
                        "Division before multiplication in `{}` may cause precision loss.",
                        fn_name
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: i as u32 + 1,
                    }],
                    affected_functions: vec![fn_name],
                    confidence: 0.60,
                    action_hint: Some("write_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Multiply before dividing to preserve precision\nlet result = (a * b) / c;".into(),
                        explanation: "Perform multiplication before division to minimize truncation errors in integer math.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct MoveAcquiresRule;

impl DetectionRule for MoveAcquiresRule {
    fn check_name(&self) -> &str { "move-missing-acquires" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let accesses_global = line.contains("borrow_global") ||
                line.contains("move_from") || line.contains("move_to");

            if !accesses_global { continue; }

            let fn_name = find_move_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            let fn_header_range = lines[..=i].iter().rev()
                .take(20)
                .any(|l| l.contains("acquires"));

            if fn_header_range { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::AccessControl,
                severity: FindingSeverity::Low,
                description: format!(
                    "Function `{}` accesses global storage without `acquires` annotation.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.55,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "public fun my_function() acquires MyResource {".into(),
                    explanation: "Add the acquires annotation to declare which resources the function accesses.".into(),
                }),
            });
        }

        matches
    }
}

struct MoveUnprotectedEntryRule;

impl DetectionRule for MoveUnprotectedEntryRule {
    fn check_name(&self) -> &str { "move-unprotected-entry" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            let is_entry = t.starts_with("public entry fun ") ||
                t.starts_with("entry fun ");
            if !is_entry { continue; }

            let takes_signer = t.contains("&signer") || t.contains("&mut signer");
            if takes_signer { continue; }

            let fn_name = t.split("fun ").nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| format!("fn_at_line_{}", i + 1));

            let body = extract_function_body(&lines, i);
            let touches_global = body.iter().any(|(_, l)| {
                l.contains("borrow_global") || l.contains("move_to") ||
                l.contains("move_from") || l.contains("global_mut")
            });

            if !touches_global { continue; }

            let description = format!(
                "Public entry function `{fn_name}` mutates global storage without taking a \
                 `&signer` parameter. There is no way to verify who called it — any \
                 account can invoke this."
            );
            let patched = format!(
                "public entry fun {fn_name}(_signer: &signer, ...) acquires T {{\n\
                 \x20   let addr = signer::address_of(_signer);\n\
                 \x20   assert!(exists<T>(addr), ENO_NOT_OWNER);\n\
                 \x20   ...\n\
                 }}"
            );
            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::AccessControl,
                severity: FindingSeverity::High,
                description,
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.82,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched,
                    explanation: "Take a &signer and assert caller identity before mutating global state.".into(),
                }),
            });
        }

        matches
    }
}

struct MoveSharedObjectRule;

impl DetectionRule for MoveSharedObjectRule {
    fn check_name(&self) -> &str { "move-unconstrained-shared-object" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("share_object(") { continue; }

            let fn_name = find_move_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            let window_start = i.saturating_sub(15);
            let has_guard = lines[window_start..=i].iter().any(|l| {
                l.contains("assert!") || l.contains("assert_eq!") ||
                l.contains("assert_ne!")
            });

            if has_guard { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("SharedObjectAbuse".into()),
                severity: FindingSeverity::Medium,
                description: format!(
                    "`share_object` called in `{}` without preceding assertions. \
                     Any user may be able to create shared objects of this type and \
                     manipulate globally accessible state.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.62,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// Validate ownership/params before sharing:\n\
                              // assert!(object::id(&obj) == expected_id, EWRONG_OBJECT);\n\
                              // assert!(signer::address_of(s) == creator, ENOT_CREATOR);\n\
                              // share_object(obj);".into(),
                    explanation: "Assert object identity and creator authority before making an object shared.".into(),
                }),
            });
        }

        matches
    }
}

struct MoveAccessControlRule;

impl DetectionRule for MoveAccessControlRule {
    fn check_name(&self) -> &str { "move-missing-access-check" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let is_mutating = line.contains("borrow_global_mut<") ||
                line.contains("move_from<") || line.contains("move_to<");
            if !is_mutating { continue; }

            let fn_name = find_move_function(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            let window_start = i.saturating_sub(20);
            let has_check = lines[window_start..=i].iter().any(|l| {
                l.contains("assert!(") && (l.contains("address_of") ||
                    l.contains("== expected") || l.contains("owner") ||
                    l.contains("admin") || l.contains("assert_eq!"))
            }) || lines[window_start..=i].iter().any(|l| {
                l.contains("assert_eq!(") || l.contains("assert_ne!(")
            });

            if has_check { continue; }

            let fn_line = lines[..=i].iter().rev()
                .find(|l| l.trim().starts_with("public") || l.trim().starts_with("entry") ||
                      l.trim().starts_with("fun "))
                .cloned()
                .unwrap_or("");
            let is_entry = fn_line.contains("entry") || fn_line.contains("public entry");
            let takes_signer = fn_line.contains("&signer");

            if takes_signer && !is_entry { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::AccessControl,
                severity: FindingSeverity::High,
                description: format!(
                    "Global storage mutation in `{fn_name}` without any authority assertion \
                     (`assert!` on signer address or owner). Any caller may mutate this resource."
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.70,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched: "let addr = signer::address_of(s);\n\
                              assert!(exists<Config>(addr), ENO_CONFIG);\n\
                              assert!(addr == @admin, EUNAUTHORIZED);\n\
                              let cfg = borrow_global_mut<Config>(addr);".into(),
                    explanation: "Verify the signer's address against an expected authority before mutating global storage.".into(),
                }),
            });
        }

        matches
    }
}

struct MovePublicMutatorRule;

impl DetectionRule for MovePublicMutatorRule {
    fn check_name(&self) -> &str { "move-public-mutator" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            let is_plain_public = t.starts_with("public fun ") && !t.contains("&signer");
            if !is_plain_public { continue; }

            let fn_name = t.split("fun ").nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if fn_name.is_empty() { continue; }

            let body = extract_function_body(&lines, i);
            let mutates = body.iter().any(|(_, l)| {
                l.contains("borrow_global_mut<") || l.contains("move_to<") ||
                l.contains("move_from<")
            });

            if !mutates { continue; }

            let takes_witness = body.iter().any(|(_, l)| {
                l.contains("_: ") || l.contains("witness")
            }) || t.contains("_:");

            let witness_note = if takes_witness { " (witness guard present — verify it is `phantom`)" } else { "" };
            let description = format!(
                "Non-entry `public fun {fn_name}` mutates global storage and is callable by \
                 any module that depends on this one{witness_note}. Consider `public(friend)` to \
                 restrict the surface area."
            );
            let patched = format!(
                "public(friend) fun {fn_name}(...) {{ ... }}\n\
                 friend <trusted_module>;"
            );
            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::AccessControl,
                severity: if takes_witness { FindingSeverity::Low } else { FindingSeverity::Medium },
                description,
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.55,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched,
                    explanation: "Restrict mutating functions to friend modules, or require a one-time-witness capability argument.".into(),
                }),
            });
        }

        matches
    }
}

struct FeltOverflowRule;

impl DetectionRule for FeltOverflowRule {
    fn check_name(&self) -> &str { "felt-overflow" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let uses_felt = line.contains("felt252") || line.contains(": felt");
            let has_arithmetic = line.contains('+') || line.contains('*') || line.contains('-');
            let has_range_check = lines[i.saturating_sub(2)..lines.len().min(i + 3)]
                .iter()
                .any(|l| l.contains("assert") || l.contains("range_check"));

            if uses_felt && has_arithmetic && !has_range_check {
                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::FeltOverflow,
                    severity: FindingSeverity::Medium,
                    description: format!(
                        "Arithmetic on felt252 at line {} without range check. \
                         Felt arithmetic wraps modulo P, which can cause unexpected behavior.",
                        i + 1
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: i as u32 + 1,
                    }],
                    affected_functions: vec!["<unknown>".into()],
                    confidence: 0.60,
                    action_hint: Some("write_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Use u256 instead of felt252 for financial values\n// Or add explicit range checks with assert".into(),
                        explanation: "Use bounded integer types (u128/u256) instead of felt252 for values that shouldn't wrap.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct CairoReentrancyRule;

impl DetectionRule for CairoReentrancyRule {
    fn check_name(&self) -> &str { "cairo-reentrancy" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("call_contract_syscall") && !line.contains("invoke(") {
                continue;
            }

            let writes_after = lines[i..lines.len().min(i + 10)]
                .iter()
                .any(|l| l.contains("write(") || l.contains("::write(") || l.contains("store"));

            if writes_after {
                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::Reentrancy,
                    severity: FindingSeverity::High,
                    description: format!(
                        "External call at line {} with state write after. Potential reentrancy in Cairo contract.",
                        i + 1
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: (i + 10).min(lines.len().saturating_sub(1)) as u32 + 1,
                    }],
                    affected_functions: vec!["<unknown>".into()],
                    confidence: 0.75,
                    action_hint: Some("external_call".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Write state before making external calls\n// Apply Checks-Effects-Interactions pattern".into(),
                        explanation: "Update contract state before calling external contracts to prevent reentrancy.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct CairoUnprotectedWriteRule;

impl DetectionRule for CairoUnprotectedWriteRule {
    fn check_name(&self) -> &str { "cairo-unprotected-storage-write" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            let is_external = t.starts_with("#[external(v0)]") ||
                t.starts_with("#[abi(embed_v0)]") || t.starts_with("#[external]");
            if !is_external { continue; }

            let sig_idx = (i + 1..lines.len().min(i + 4))
                .find(|j| lines.get(*j).is_some_and(|l| l.contains("fn ") && l.contains('(')));

            let Some(sig_idx) = sig_idx else { continue };

            let sig = lines.get(sig_idx).copied().unwrap_or("");
            if !sig.contains("pub fn ") && !sig.contains("fn ") { continue; }

            let fn_name = sig.split("fn ").nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if fn_name.is_empty() { continue; }

            let body_end = find_cairo_body_end(&lines, sig_idx);
            let body = &lines[sig_idx..=body_end];

            let writes_storage = body.iter().any(|l| {
                l.contains(".write(") || l.contains("::write(") ||
                l.contains(".update(") || l.contains(".append(")
            });

            if !writes_storage { continue; }

            let has_caller_check = body.iter().any(|l| {
                l.contains("get_caller_address()") &&
                    (l.contains("==") || l.contains("assert") || l.contains("require"))
            }) || body.iter().any(|l| {
                l.contains("assert(") && (l.contains("owner") || l.contains("caller") ||
                    l.contains("admin") || l.contains("authorized"))
            });

            if has_caller_check { continue; }

            let description = format!(
                "External function `{fn_name}` writes contract storage without verifying \
                 `get_caller_address()`. In Starknet's account-abstraction model, \
                 any account contract can invoke this entry point."
            );
            let patched = format!(
                "// #[external(v0)]\n\
                 // pub fn {fn_name}(...) {{\n\
                 // \x20   assert!(get_caller_address() == owner::read(), 'NOT_OWNER');\n\
                 // \x20   ...\n\
                 // }}"
            );
            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::AccessControl,
                severity: FindingSeverity::High,
                description,
                affected_lines: vec![LineRange {
                    start: sig_idx as u32 + 1,
                    end: sig_idx as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.80,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched,
                    explanation: "Assert get_caller_address() against the stored owner before mutating state.".into(),
                }),
            });
        }

        matches
    }
}

fn find_cairo_body_end(lines: &[&str], sig_idx: usize) -> usize {
    let mut depth = 0i32;
    let mut started = false;

    for (i, line) in lines.iter().enumerate().skip(sig_idx) {
        for ch in line.chars() {
            if ch == '{' { depth += 1; started = true; }
            if ch == '}' { depth -= 1; }
        }
        if started && depth <= 0 { return i; }
    }

    lines.len().saturating_sub(1)
}

struct CairoMissingEventRule;

impl DetectionRule for CairoMissingEventRule {
    fn check_name(&self) -> &str { "cairo-missing-event" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_event_system = source.contains("#[derive(") && source.contains("Event") ||
            source.contains("emit(") || source.contains("Event::");

        if !has_event_system { return matches; }

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if !(t.starts_with("#[external(v0)]") || t.starts_with("#[abi(embed_v0)]")) {
                continue;
            }

            let sig_idx = (i + 1..lines.len().min(i + 4))
                .find(|j| lines.get(*j).is_some_and(|l| l.contains("fn ") && l.contains('(')));
            let Some(sig_idx) = sig_idx else { continue };

            let fn_name = lines.get(sig_idx).copied().unwrap_or("").split("fn ").nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if fn_name.is_empty() { continue; }

            let body_end = find_cairo_body_end(&lines, sig_idx);
            let body = &lines[sig_idx..=body_end];

            let writes_storage = body.iter().any(|l| {
                l.contains(".write(") || l.contains("::write(") || l.contains(".update(")
            });

            if !writes_storage { continue; }

            let emits_event = body.iter().any(|l| {
                l.contains("emit(") || l.contains("Event {") ||
                l.contains("syscalls.emit")
            });

            if emits_event { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("MissingEvent".into()),
                severity: FindingSeverity::Low,
                description: format!(
                    "State-changing external function `{}` mutates storage without emitting \
                     an event. Indexers and off-chain watchers lose track of state transitions.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: sig_idx as u32 + 1,
                    end: sig_idx as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.60,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// emit(Event::StateUpdated { caller: get_caller_address(), new_value });".into(),
                    explanation: "Emit an event alongside storage mutations so indexers can track state.".into(),
                }),
            });
        }

        matches
    }
}

struct CairoUpgradeRule;

impl DetectionRule for CairoUpgradeRule {
    fn check_name(&self) -> &str { "cairo-unprotected-upgrade" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let is_upgrade = line.contains("replace_class_syscall") ||
                line.contains("replace_class(");
            if !is_upgrade { continue; }

            let fn_name = find_cairo_enclosing_fn(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            let window_start = i.saturating_sub(20);
            let has_owner_check = lines[window_start..=i].iter().any(|l| {
                l.contains("get_caller_address()") && (l.contains("==") || l.contains("assert"))
            }) || lines[window_start..=i].iter().any(|l| {
                l.contains("assert!(") && (l.contains("owner") || l.contains("admin"))
            });

            if has_owner_check { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::AccessControl,
                severity: FindingSeverity::High,
                description: format!(
                    "`replace_class_syscall` (contract upgrade) invoked in `{}` without \
                     owner verification. Anyone can upgrade the class hash and take over \
                     the contract's logic.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.85,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched: "assert!(get_caller_address() == upgrade_owner::read(), 'NOT_OWNER');\n\
                              replace_class_syscall(new_class_hash).unwrap_syscall();".into(),
                    explanation: "Restrict class replacement to a trusted owner, ideally behind a timelock/governance check.".into(),
                }),
            });
        }

        matches
    }
}

fn find_cairo_enclosing_fn(lines: &[&str], line_idx: usize) -> Option<String> {
    for line in lines[..=line_idx].iter().rev() {
        if line.contains("fn ") && line.contains('(') && !line.trim_start().starts_with("//") {
            return line.split("fn ").nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string());
        }
    }
    None
}

struct CairoUnsafeUnwrapRule;

impl DetectionRule for CairoUnsafeUnwrapRule {
    fn check_name(&self) -> &str { "cairo-unsafe-unwrap" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let syscall_apis = [
            "call_contract_syscall", "send_message_to_l1_syscall",
            "replace_class_syscall", "get_execution_info", "storage_read_syscall",
            "storage_write_syscall", "deploy_syscall",
        ];

        for (i, line) in lines.iter().enumerate() {
            if !line.contains(".unwrap_syscall()") { continue; }
            if line.trim().starts_with("//") { continue; }

            let is_risky_syscall = syscall_apis.iter().any(|api| line.contains(api));
            let is_result_unwrap = line.contains(".unwrap()");

            if !is_risky_syscall && !is_result_unwrap { continue; }

            let fn_name = find_cairo_enclosing_fn(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            let severity = if is_risky_syscall {
                FindingSeverity::Medium
            } else {
                FindingSeverity::Low
            };

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("UncheckedSyscallResult".into()),
                severity,
                description: format!(
                    "Unchecked syscall/result unwrap in `{}`. If the syscall fails, \
                     panics with an unhelpful error (or skips validation) instead of \
                     handling the failure explicitly.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.50,
                action_hint: Some("call".into()),
                fix_hint: Some(FixHint {
                    patched: "// let result = call_contract_syscall(addr, selector, calldata)?;\n\
                              // let result = result.map_err(|e| Errors::CALL_FAILED)?;\n\
                              " .trim_end().into(),
                    explanation: "Propagate syscall failures with `?` or match on them so errors are handled deliberately.".into(),
                }),
            });
        }

        matches
    }
}

struct ValidatorBypassRule;

impl DetectionRule for ValidatorBypassRule {
    fn check_name(&self) -> &str { "validator-bypass" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            if !line.contains("validator") && !line.contains("fn validate") {
                continue;
            }

            let window = &lines[i..lines.len().min(i + 30)];
            let always_true = window.iter().any(|l| l.contains("True")) &&
                !window.iter().any(|l| l.contains("False")) &&
                !window.iter().any(|l| l.contains("fail")) &&
                !window.iter().any(|l| l.contains("expect"));

            if always_true {
                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::ValidatorBypass,
                    severity: FindingSeverity::High,
                    description: format!(
                        "Validator near line {} appears to always return True without meaningful checks.",
                        i + 1
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: (i + 5).min(lines.len().saturating_sub(1)) as u32 + 1,
                    }],
                    affected_functions: vec!["validator".into()],
                    confidence: 0.70,
                    action_hint: Some("read_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Add proper datum/redeemer validation logic\n// Check signatures, datum conditions, and transaction outputs".into(),
                        explanation: "Validators must enforce meaningful constraints on spending conditions.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct AikenDatumHijackRule;

impl DetectionRule for AikenDatumHijackRule {
    fn check_name(&self) -> &str { "aiken-datum-hijack" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if !t.starts_with("spend(") && !t.starts_with("spend ") { continue; }

            let body_end = find_aiken_handler_end(&lines, i);
            let body = &lines[i..=body_end];

            let validates_datum = body.iter().any(|l| {
                let lt = l.trim();
                lt.contains("expect Some(") || lt.contains("expect Ok(") ||
                (lt.contains("datum") && (lt.contains("==") || lt.contains("match") ||
                    lt.contains("expect")))
            });

            if validates_datum { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("DatumHijacking".into()),
                severity: FindingSeverity::High,
                description: format!(
                    "`spend` validator at line {} never validates its datum. An attacker can \
                     spend the script UTXO by attaching an arbitrary datum (or None), \
                     bypassing the state the script was supposed to enforce.",
                    i + 1
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: body_end as u32 + 1,
                }],
                affected_functions: vec!["spend".into()],
                confidence: 0.72,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "spend(datum: Option<Datum>, redeemer: Redeemer, self: OutputReference, tx: Transaction) {\n\
                              \x20   expect Some(d) = datum\n\
                              \x20   assert d.owner == tx.extra_signatories.at(0)\n\
                              \x20   ...\n\
                              }".into(),
                    explanation: "Pattern-match the datum with `expect` and assert its fields before authorizing the spend.".into(),
                }),
            });
        }

        matches
    }
}

fn find_aiken_handler_end(lines: &[&str], handler_start: usize) -> usize {
    let mut depth = 0i32;
    let mut started = false;

    for (i, line) in lines.iter().enumerate().skip(handler_start) {
        let t = line.trim();

        if started && depth <= 1 && i > handler_start {
            let is_next_handler = ["spend(", "mint(", "burn(", "withdraw(", "update(", "else("]
                .iter().any(|k| t.starts_with(k));
            if is_next_handler && depth <= 1 { return i.saturating_sub(1); }
            if t == "}" && depth <= 1 && !t.contains('{') { return i; }
        }

        for ch in line.chars() {
            if ch == '{' { depth += 1; started = true; }
            if ch == '}' { depth -= 1; }
        }

        if started && depth <= 0 { return i; }
    }

    lines.len().saturating_sub(1)
}

struct AikenDoubleSatisfactionRule;

impl DetectionRule for AikenDoubleSatisfactionRule {
    fn check_name(&self) -> &str { "aiken-double-satisfaction" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if !t.starts_with("spend(") && !t.starts_with("spend ") { continue; }

            let body_end = find_aiken_handler_end(&lines, i);
            let body = &lines[i..=body_end];

            let checks_outputs = body.iter().any(|l| {
                l.contains("tx.outputs") || l.contains("list.any") ||
                l.contains("outputs.any")
            });

            if !checks_outputs { continue; }

            let ties_to_self = body.iter().any(|l| {
                l.contains("self.value") || l.contains("self.output_reference") ||
                l.contains("self.datum") || l.contains("tx.inputs") ||
                l.contains("own_input") || l.contains("script_purposes")
            });

            if ties_to_self { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("DoubleSatisfaction".into()),
                severity: FindingSeverity::High,
                description: format!(
                    "`spend` validator at line {} checks transaction outputs but never ties \
                     the check to its own input (`self.value` / `self.output_reference` / \
                     `tx.inputs`). A single crafted output can satisfy this validator and \
                     another validator simultaneously (double satisfaction).",
                    i + 1
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: body_end as u32 + 1,
                }],
                affected_functions: vec!["spend".into()],
                confidence: 0.65,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// Anchor outputs to this script's own input value:\n\
                              // let own_value = self.value\n\
                              // assert sum_of(matched_outputs) == own_value\n\
                              // or verify tx.inputs contains self.output_reference".into(),
                    explanation: "Bind output assertions to the validator's own input so one output cannot satisfy two scripts.".into(),
                }),
            });
        }

        matches
    }
}

struct AikenMintBoundaryRule;

impl DetectionRule for AikenMintBoundaryRule {
    fn check_name(&self) -> &str { "aiken-missing-boundary-validation" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if !t.starts_with("mint(") && !t.starts_with("burn(") { continue; }

            let body_end = find_aiken_handler_end(&lines, i);
            let body = &lines[i..=body_end];

            let handler = if t.starts_with("mint(") { "mint" } else { "burn" };

            let has_boundary_check = body.iter().any(|l| {
                (l.contains("assert") || l.contains("expect") || l.contains("==")) &&
                    (l.contains("quantity") || l.contains("assets") ||
                        l.contains("tx.mint") || l.contains("value") ||
                        l.contains("expected"))
            });

            if has_boundary_check { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("MissingBoundaryValidation".into()),
                severity: FindingSeverity::High,
                description: format!(
                    "`{}` handler at line {} does not assert exact minted/burned quantities. \
                     Without an exact boundary check, unauthorized token amounts can be \
                     minted or burned within the same transaction.",
                    handler, i + 1
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: body_end as u32 + 1,
                }],
                affected_functions: vec![handler.into()],
                confidence: 0.68,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// expect quantity = tx.mint.get(policy_id)\n\
                              // assert quantity == expected_amount\n\
                              // assert quantity == negate(if burning)".into(),
                    explanation: "Assert the exact asset quantity being minted or burned against the authorized amount.".into(),
                }),
            });
        }

        matches
    }
}

struct AikenMissingSignatoryRule;

impl DetectionRule for AikenMissingSignatoryRule {
    fn check_name(&self) -> &str { "aiken-missing-signatory" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_signer_apis = source.contains("extra_signatories") ||
            source.contains("find_signer") || source.contains("verified_signed") ||
            source.contains("signatories");

        if has_signer_apis { return matches; }

        let is_validator = source.contains("validator {") || source.contains("validator{");
        if !is_validator { return matches; }

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            if !t.starts_with("spend(") && !t.starts_with("spend ") { continue; }

            let body_end = find_aiken_handler_end(&lines, i);

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::MissingSigner,
                severity: FindingSeverity::Medium,
                description: format!(
                    "Validator contains no signatory checks anywhere in the module \
                     (no `extra_signatories` / `find_signer` / `verified_signed`). \
                     The `spend` handler at line {} authorizes spending without proving \
                     any signature.",
                    i + 1
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: body_end as u32 + 1,
                }],
                affected_functions: vec!["spend".into()],
                confidence: 0.58,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// expect owner = find_signer(tx.extra_signatories, owner_pub_key)\n\
                              // or: assert tx.verified_signed(owner_pub_key)".into(),
                    explanation: "Verify a required signature via extra_signatories or verified_signed before authorizing.".into(),
                }),
            });
        }

        matches
    }
}

struct AikenTimeRangeRule;

impl DetectionRule for AikenTimeRangeRule {
    fn check_name(&self) -> &str { "aiken-unchecked-time-range" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let uses_time = source.contains("deadline") || source.contains("valid_until") ||
            source.contains("expires") || source.contains("timeout") ||
            source.contains("start_time");

        if !uses_time { return matches; }

        let checks_range = source.contains("valid_range") ||
            source.contains("before") || source.contains("after") ||
            source.contains("contains");

        if checks_range { return matches; }

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            let is_handler = t.starts_with("spend(") || t.starts_with("mint(") ||
                t.starts_with("withdraw(") || t.starts_with("update(");
            if !is_handler { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("TimeRangeMisuse".into()),
                severity: FindingSeverity::Medium,
                description: format!(
                    "Contract defines time-based terms (deadline/timeout) but no handler \
                     at line {} consults `tx.valid_range`. Time constraints are declared \
                     yet never enforced on-chain.",
                    i + 1
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![t.split('(').next().unwrap_or("handler").to_string()],
                confidence: 0.55,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// assert tx.valid_range.lower + deadline > tx.valid_range.upper\n\
                              // or: expect True = tx.valid_range.within(deadline_range)".into(),
                    explanation: "Enforce the deadline by checking tx.valid_range against the declared time bounds.".into(),
                }),
            });
        }

        matches
    }
}

struct CompactStateLeakRule;

impl DetectionRule for CompactStateLeakRule {
    fn check_name(&self) -> &str { "compact-state-leak" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let exposes_state = (line.contains("pub") || line.contains("export")) &&
                (line.contains("secret") || line.contains("private") || line.contains("confidential"));

            if exposes_state {
                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::AccessControl,
                    severity: FindingSeverity::High,
                    description: format!(
                        "Potential confidential state exposure at line {}. \
                         Public/exported members should not contain private data.",
                        i + 1
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: i as u32 + 1,
                    }],
                    affected_functions: vec!["<unknown>".into()],
                    confidence: 0.55,
                    action_hint: Some("read_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Keep confidential data in private state; only expose commitments or proofs".into(),
                        explanation: "In privacy-preserving contracts, never export raw confidential values.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct CompactPrivateLeakRule;

impl DetectionRule for CompactPrivateLeakRule {
    fn check_name(&self) -> &str { "compact-private-state-leak" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let private_vars: Vec<(usize, String)> = lines.iter().enumerate()
            .filter_map(|(i, l)| {
                let t = l.trim();
                if !t.contains("private") && !t.contains("confidential") { return None; }
                if t.starts_with("//") || t.starts_with("*") { return None; }
                let name = t.replace("private", "")
                    .replace("confidential", "")
                    .replace(':', " ")
                    .split_whitespace()
                    .next()
                    .map(|s| s.trim_end_matches('=').to_string());
                name.map(|n| (i, n))
            })
            .collect();

        if private_vars.is_empty() { return matches; }

        for (i, line) in lines.iter().enumerate() {
            let is_exposure = line.contains("log(") || line.contains("reveal(") ||
                line.contains("emit(") || line.contains("publicLog(");
            if !is_exposure { continue; }
            if line.trim().starts_with("//") { continue; }

            let leaked = private_vars.iter().find(|(_, name)| {
                !name.is_empty() && name.len() > 2 && line.contains(name.as_str())
            });

            if let Some((decl_line, name)) = leaked {
                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::Other("PrivateStateLeak".into()),
                    severity: FindingSeverity::High,
                    description: format!(
                        "Private state `{}` (declared line {}) passed to a public log/reveal \
                         at line {}. In Compact, `log`/`reveal` writes to the public ledger — \
                         this permanently destroys the confidentiality of the private value.",
                        name, decl_line + 1, i + 1
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: i as u32 + 1,
                    }],
                    affected_functions: vec!["<contract>".into()],
                    confidence: 0.80,
                    action_hint: Some("read_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Log only a commitment/hash instead of the raw value:\n\
                                  // log(hash(privateValue));\n\
                                  // Keep raw private state in witness/local storage.".into(),
                        explanation: "Never reveal raw private state on-chain; publish hashes or zero-knowledge proofs of properties instead.".into(),
                    }),
                });
            }
        }

        matches
    }
}

struct CompactWitnessLogRule;

impl DetectionRule for CompactWitnessLogRule {
    fn check_name(&self) -> &str { "compact-witness-exposure" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let mut witness_ranges: Vec<(usize, usize, String)> = Vec::new();

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            let is_witness = t.contains("witness") &&
                (t.contains("function") || t.starts_with("witness") ||
                 t.contains("@witness") || t.contains("WitnessContext"));

            if !is_witness { continue; }

            let body_end = find_ts_block_end(&lines, i);
            let name = t.split('(').next()
                .map(|s| s.replace("witness", "").trim().trim_matches(|c: char| !c.is_alphanumeric() && c != '_').to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("witness_at_line_{}", i + 1));

            witness_ranges.push((i, body_end, name));
        }

        for (start, end, name) in &witness_ranges {
            for (offset, line) in lines[*start..=*end].iter().enumerate() {
                let j = *start + offset;
                let exposes = line.contains("log(") || line.contains("reveal(") ||
                    line.contains("emit(") || line.contains("console.");
                if !exposes { continue; }
                if line.trim().starts_with("//") { continue; }

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::Other("WitnessExposure".into()),
                    severity: FindingSeverity::High,
                    description: format!(
                        "Witness function `{}` (line {}) logs or reveals data. Witness \
                         functions handle user secrets off-chain; logging their contents \
                         leaks credentials into the transaction record.",
                        name, start + 1
                    ),
                    affected_lines: vec![LineRange {
                        start: j as u32 + 1,
                        end: j as u32 + 1,
                    }],
                    affected_functions: vec![name.clone()],
                    confidence: 0.75,
                    action_hint: Some("read_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Return secrets only to the local proving context:\n\
                                  // return { secret: userSecret };\n\
                                  // Never call log()/reveal() on witness-owned values.".into(),
                        explanation: "Witness outputs stay local for proof generation; anything logged becomes public ledger data.".into(),
                    }),
                });
            }
        }

        matches
    }
}

fn find_ts_block_end(lines: &[&str], start: usize) -> usize {
    let mut depth = 0i32;
    let mut started = false;

    for (i, line) in lines.iter().enumerate().skip(start) {
        for ch in line.chars() {
            if ch == '{' { depth += 1; started = true; }
            if ch == '}' { depth -= 1; }
        }
        if started && depth <= 0 { return i; }
    }

    lines.len().saturating_sub(1)
}

struct CompactUnderConstrainedRule;

impl DetectionRule for CompactUnderConstrainedRule {
    fn check_name(&self) -> &str { "compact-underconstrained-action" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let is_action = line.contains("@action") || line.contains("@settlement");
            if !is_action { continue; }

            let sig_idx = (i + 1..lines.len().min(i + 5))
                .find(|j| lines.get(*j).is_some_and(|l| l.contains('(') &&
                    (l.contains("async") || l.contains("Transaction"))));

            let Some(sig_idx) = sig_idx else { continue };

            let fn_name = lines.get(sig_idx).copied().unwrap_or("").split('(').next()
                .map(|s| s.replace("async", "").replace("fn", "").replace(":", "").trim().to_string())
                .unwrap_or_else(|| format!("action_at_line_{}", sig_idx + 1));

            let body_end = find_ts_block_end(&lines, sig_idx);
            let body = &lines[sig_idx..=body_end];

            let mutates = body.iter().any(|l| {
                l.contains(".value =") || l.contains(".set(") ||
                l.contains(".increment(") || l.contains(".decrement(") ||
                l.contains(".insert(") || l.contains(".delete(") ||
                l.contains(".append(") || l.contains(".put(")
            });

            if !mutates { continue; }

            let has_assert = body.iter().any(|l| {
                let t = l.trim();
                t.contains("assert(") || t.starts_with("if (") || t.contains("throw")
            });

            if has_assert { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("UnderConstrainedCircuit".into()),
                severity: FindingSeverity::Medium,
                description: format!(
                    "Action `{}` mutates ledger/private state without any `assert` on its \
                     arguments. Under-constrained actions accept arbitrary witness inputs — \
                     the ZK circuit proves execution but not intent.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: sig_idx as u32 + 1,
                    end: sig_idx as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.60,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// assert(recipient !== undefined);\n\
                              // assert(amount > 0n && amount <= balance);\n\
                              // assert(senderKnowsSecret(proof));".into(),
                    explanation: "Constrain every private/public input with assertions so the circuit enforces business rules.".into(),
                }),
            });
        }

        matches
    }
}

struct QuorlinPermissionRule;

impl DetectionRule for QuorlinPermissionRule {
    fn check_name(&self) -> &str { "quorlin-permission" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let state_mutation = line.contains("mutate") || line.contains("set_state") ||
                line.contains("update(") || line.contains("delete(");

            if !state_mutation { continue; }

            let has_permission_check = lines[i.saturating_sub(5)..=i]
                .iter()
                .any(|l| l.contains("require_auth") || l.contains("check_permission") ||
                    l.contains("authorized"));

            if !has_permission_check {
                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::AccessControl,
                    severity: FindingSeverity::High,
                    description: format!(
                        "State mutation at line {} without permission check.",
                        i + 1
                    ),
                    affected_lines: vec![LineRange {
                        start: i as u32 + 1,
                        end: i as u32 + 1,
                    }],
                    affected_functions: vec!["<unknown>".into()],
                    confidence: 0.60,
                    action_hint: Some("write_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Add require_auth(caller) before state mutations".into(),
                        explanation: "All state-mutating operations should verify caller authorization.".into(),
                    }),
                });
            }
        }

        matches
    }
}

/// QL-AC-01: `writes` function with no `require` at all (Critical → High)
struct QuorlinUnrestrictedWriteRule;

impl DetectionRule for QuorlinUnrestrictedWriteRule {
    fn check_name(&self) -> &str { "QL-AC-01" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (fn_start, fn_name, is_writes) in find_quorlin_functions(&lines) {
            if !is_writes { continue; }

            let fn_body = extract_function_body(&lines, fn_start);
            let has_require = fn_body.iter().any(|(_, l)| {
                let t = l.trim();
                t.starts_with("require ") || t.starts_with("require(")
            });

            if has_require { continue; }

            let description = format!(
                "Unrestricted `writes` function `{fn_name}`: no `require` statement anywhere \
                 in the body. Any caller can invoke it unconditionally."
            );
            let patched = format!(
                "writes {fn_name}(... ) {{\n\
                 \x20   require caller == owner, \"not owner\";\n\
                 \x20   require paused == no, \"paused\";\n\
                 \x20   ...\n\
                 }}"
            );
            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::AccessControl,
                severity: FindingSeverity::High,
                description,
                affected_lines: vec![LineRange {
                    start: fn_start as u32 + 1,
                    end: fn_start as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.90,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched,
                    explanation: "Every `writes` function must gate on caller identity and contract state via `require`.".into(),
                }),
            });
        }

        matches
    }
}

/// QL-AC-02: Privileged state modified without a `caller` check (Critical → High)
struct QuorlinPrivilegedWriteRule;

impl DetectionRule for QuorlinPrivilegedWriteRule {
    fn check_name(&self) -> &str { "QL-AC-02" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        const PRIVILEGED: &[&str] = &[
            "owner", "paused", "supply", "masterMinter", "blocklister",
            "pendingOwner", "isMinter",
        ];

        for (fn_start, fn_name, is_writes) in find_quorlin_functions(&lines) {
            if !is_writes { continue; }

            let fn_body = extract_function_body(&lines, fn_start);

            let has_caller_require = fn_body.iter().any(|(_, l)| {
                let t = l.trim();
                (t.starts_with("require ") || t.starts_with("require(")) &&
                    t.contains("caller")
            });

            if has_caller_require { continue; }

            for (line_no, line) in &fn_body {
                let Some(target) = quorlin_state_assign_target(line) else { continue };

                if !PRIVILEGED.iter().any(|p| target == *p) { continue; }

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::AccessControl,
                    severity: FindingSeverity::High,
                    description: format!(
                        "Privileged state `{target}` assigned in `{fn_name}` with no `require` referencing \
                         `caller`. Any address can modify privileged contract state."
                    ),
                    affected_lines: vec![LineRange {
                        start: *line_no as u32 + 1,
                        end: *line_no as u32 + 1,
                    }],
                    affected_functions: vec![fn_name.clone()],
                    confidence: 0.88,
                    action_hint: Some("write_state".into()),
                    fix_hint: Some(FixHint {
                        patched: format!(
                            "require caller == owner, \"not owner\";\n{target} = ...;"
                        ),
                        explanation: "Gate assignments to privileged state behind `require caller == owner` (or a role check).".into(),
                    }),
                });
            }
        }

        matches
    }
}

/// QL-AC-03: Single-step ownership transfer (High)
struct QuorlinOwnershipTransferRule;

impl DetectionRule for QuorlinOwnershipTransferRule {
    fn check_name(&self) -> &str { "QL-AC-03" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let has_pending_owner = lines.iter().any(|l| {
            let t = l.trim();
            t.starts_with("address pendingOwner") || t.starts_with("address pendingowner")
        });

        if has_pending_owner { return matches; }

        for (fn_start, fn_name, is_writes) in find_quorlin_functions(&lines) {
            if !is_writes { continue; }

            let fn_body = extract_function_body(&lines, fn_start);

            for (line_no, line) in &fn_body {
                let Some(target) = quorlin_state_assign_target(line) else { continue };

                if target != "owner" { continue; }

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::AccessControl,
                    severity: FindingSeverity::High,
                    description: format!(
                        "Single-step ownership transfer in `{fn_name}`: direct assignment to `owner` \
                         without a `pendingOwner` handshake. A mistyped address permanently \
                         bricks ownership."
                    ),
                    affected_lines: vec![LineRange {
                        start: *line_no as u32 + 1,
                        end: *line_no as u32 + 1,
                    }],
                    affected_functions: vec![fn_name.clone()],
                    confidence: 0.80,
                    action_hint: Some("write_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Two-step pattern:\n\
                                  // writes proposeOwnership(address newOwner) { require caller == owner; pendingOwner = newOwner; }\n\
                                  // writes acceptOwnership() { require caller == pendingOwner; owner = pendingOwner; }".into(),
                        explanation: "Use a pendingOwner two-step transfer so the new owner must accept before authority moves.".into(),
                    }),
                });
            }
        }

        matches
    }
}

/// QL-AC-04: `origin` used for authorization instead of `caller` (High)
struct QuorlinOriginAuthRule;

impl DetectionRule for QuorlinOriginAuthRule {
    fn check_name(&self) -> &str { "QL-AC-04" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (i, line) in lines.iter().enumerate() {
            let t = line.trim();
            let is_require = t.starts_with("require ") || t.starts_with("require(");
            if !is_require { continue; }
            if !t.contains("origin") { continue; }
            if !t.contains("origin ==") && !t.contains("origin ==") &&
                !t.contains("== origin") && !t.contains("origin !=") {
                continue;
            }

            let fn_name = find_quorlin_enclosing_fn(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::TxOriginAuth,
                severity: FindingSeverity::High,
                description: format!(
                    "`origin` used for authorization in `{}`. Quorlin's `origin` equals \
                     EVM tx.origin — a phishing contract can relay calls and satisfy the check.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.92,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "require caller == owner, \"not owner\";".into(),
                    explanation: "Replace `origin` with `caller` so only the immediate caller passes the check.".into(),
                }),
            });
        }

        matches
    }
}

/// QL-IV-01: Address param not checked against `nobody` (Medium)
struct QuorlinNobodyCheckRule;

impl DetectionRule for QuorlinNobodyCheckRule {
    fn check_name(&self) -> &str { "QL-IV-01" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (fn_start, fn_name, is_writes) in find_quorlin_functions(&lines) {
            if !is_writes { continue; }

            let header = lines.get(fn_start).copied().unwrap_or("");
            if !header.contains("address") { continue; }

            let fn_body = extract_function_body(&lines, fn_start);
            if fn_body.iter().any(|(_, l)| l.contains("nobody")) { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("InputValidation".into()),
                severity: FindingSeverity::Medium,
                description: format!(
                    "`writes` function `{}` accepts `address` parameters but never checks \
                     them against `nobody` (the zero address). Transfers to `nobody` \
                     permanently burn funds.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: fn_start as u32 + 1,
                    end: fn_start as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.65,
                action_hint: Some("read_state".into()),
                fix_hint: Some(FixHint {
                    patched: "require recipient != nobody, \"zero address\";".into(),
                    explanation: "Reject the named zero-address keyword `nobody` for every address parameter.".into(),
                }),
            });
        }

        matches
    }
}

/// QL-IV-03: Amount param not checked > 0 (Medium)
struct QuorlinAmountZeroRule;

impl DetectionRule for QuorlinAmountZeroRule {
    fn check_name(&self) -> &str { "QL-IV-03" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let money_verbs = ["transfer", "mint", "burn", "deposit", "withdraw",
            "approve", "transferFrom", "send"];

        for (fn_start, fn_name, is_writes) in find_quorlin_functions(&lines) {
            if !is_writes { continue; }

            let is_money_fn = money_verbs.iter().any(|v|
                fn_name.eq_ignore_ascii_case(v) || fn_name.to_lowercase().contains(v));

            let header = lines.get(fn_start).copied().unwrap_or("");
            let takes_amount = header.contains("amount");

            if !is_money_fn || !takes_amount { continue; }

            let fn_body = extract_function_body(&lines, fn_start);

            let checks_positive = fn_body.iter().any(|(_, l)| {
                l.contains("amount > 0") || l.contains("amount>0") || l.contains("amount >= 1")
            });

            if checks_positive { continue; }

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::Other("InputValidation".into()),
                severity: FindingSeverity::Medium,
                description: format!(
                    "Money function `{}` takes `number amount` without `require amount > 0`. \
                     Zero-value operations waste gas, emit misleading events, and can probe \
                     state.",
                    fn_name
                ),
                affected_lines: vec![LineRange {
                    start: fn_start as u32 + 1,
                    end: fn_start as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.62,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched: "require amount > 0, \"zero amount\";".into(),
                    explanation: "Reject zero amounts at the top of transfer/mint/burn functions.".into(),
                }),
            });
        }

        matches
    }
}

/// QL-RE-01: State update after external call — CEI violation (High)
struct QuorlinCeiViolationRule;

impl DetectionRule for QuorlinCeiViolationRule {
    fn check_name(&self) -> &str { "QL-RE-01" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (fn_start, fn_name, is_writes) in find_quorlin_functions(&lines) {
            if !is_writes { continue; }

            let fn_body = extract_function_body(&lines, fn_start);

            let last_external_call = fn_body.iter().enumerate()
                .filter(|(_, (_, l))| quorlin_is_external_call(l))
                .map(|(idx, (line_no, _))| (idx, *line_no))
                .next_back();

            let Some((call_idx, call_line)) = last_external_call else { continue };

            for (_idx, (line_no, line)) in fn_body.iter().enumerate().skip(call_idx + 1) {
                if quorlin_state_assign_target(line).is_none() { continue; }

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::Reentrancy,
                    severity: FindingSeverity::High,
                    description: format!(
                        "State update after external call in `{}`: state is written at \
                         line {} following the external call at line {}. This violates \
                         Checks-Effects-Interactions and is vulnerable to reentrancy.",
                        fn_name, line_no + 1, call_line + 1
                    ),
                    affected_lines: vec![LineRange {
                        start: call_line as u32 + 1,
                        end: *line_no as u32 + 1,
                    }],
                    affected_functions: vec![fn_name],
                    confidence: 0.82,
                    action_hint: Some("external_call".into()),
                    fix_hint: Some(FixHint {
                        patched: "// Move all state writes BEFORE the external call:\n\
                                  // balances[caller] = held - amount;\n\
                                  // truth ok = token.transfer(recipient, amount);\n\
                                  // require ok, \"failed\";".into(),
                        explanation: "Apply Checks-Effects-Interactions: finish state changes before calling out to other contracts.".into(),
                    }),
                });
                break;
            }
        }

        matches
    }
}

fn quorlin_is_external_call(line: &str) -> bool {
    let t = line.trim();
    t.contains(".transfer(") || t.contains(".transferFrom(") ||
        t.contains(".approve(") || t.contains(".call(") ||
        t.contains(".deposit(") || t.contains(".withdraw(") ||
        t.contains(".onERC721Received(")
}

/// QL-RE-03: Unchecked external call return (High)
struct QuorlinUncheckedCallRule;

impl DetectionRule for QuorlinUncheckedCallRule {
    fn check_name(&self) -> &str { "QL-RE-03" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        for (fn_start, fn_name, is_writes) in find_quorlin_functions(&lines) {
            if !is_writes { continue; }

            let fn_body = extract_function_body(&lines, fn_start);

            for (line_no, line) in &fn_body {
                if !quorlin_is_external_call(line) { continue; }

                let t = line.trim();

                let assigned_var: Option<String> = {
                    if let Some((lhs, _)) = t.split_once('=') {
                        let l = lhs.trim();
                        let first = l.split_whitespace().next().unwrap_or("");
                        const QTYPES: &[&str] = &["truth", "number", "address", "text"];
                        if QTYPES.contains(&first) {
                            l.split_whitespace().nth(1).map(|s| s.to_string())
                        } else if !l.contains(' ') && !l.is_empty() {
                            Some(l.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };

                match assigned_var {
                    Some(var) => {
                        let checked = fn_body.iter().any(|(_, l)| {
                            let lt = l.trim();
                            (lt.starts_with("require ") || lt.starts_with("require(")) &&
                                lt.contains(&var)
                        });
                        if checked { continue; }

                        matches.push(RuleMatch {
                            check_name: self.check_name().into(),
                            vuln_class: VulnClass::UncheckedReturn,
                            severity: FindingSeverity::High,
                            description: format!(
                                "External call result `{var}` in `{fn_name}` is assigned but never \
                                 required to be `yes`. The call can silently fail while \
                                 the rest of the function continues."
                            ),
                            affected_lines: vec![LineRange {
                                start: *line_no as u32 + 1,
                                end: *line_no as u32 + 1,
                            }],
                            affected_functions: vec![fn_name.clone()],
                            confidence: 0.80,
                            action_hint: Some("external_call".into()),
                            fix_hint: Some(FixHint {
                                patched: format!(
                                    "require {var}, \"external call failed\";"
                                ),
                                explanation: "Assert the truth value returned by external calls before proceeding.".into(),
                            }),
                        });
                    }
                    None => {
                        if !t.contains('=') && t.ends_with(';') {
                            matches.push(RuleMatch {
                                check_name: self.check_name().into(),
                                vuln_class: VulnClass::UncheckedReturn,
                                severity: FindingSeverity::High,
                                description: format!(
                                    "External call in `{fn_name}` discards its return value entirely. \
                                     Failed calls go unnoticed."
                                ),
                                affected_lines: vec![LineRange {
                                    start: *line_no as u32 + 1,
                                    end: *line_no as u32 + 1,
                                }],
                                affected_functions: vec![fn_name.clone()],
                                confidence: 0.78,
                                action_hint: Some("external_call".into()),
                                fix_hint: Some(FixHint {
                                    patched: "truth ok = target.transfer(to, amount);\n\
                                              require ok, \"external call failed\";".into(),
                                    explanation: "Capture and assert the boolean result of external calls.".into(),
                                }),
                            });
                        }
                    }
                }
            }
        }

        matches
    }
}

/// QL-EV-01: State change without event emission (Low)
struct QuorlinEventMissingRule;

impl DetectionRule for QuorlinEventMissingRule {
    fn check_name(&self) -> &str { "QL-EV-01" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        let declares_events = lines.iter().any(|l| l.trim().starts_with("event "));
        if !declares_events { return matches; }

        for (fn_start, fn_name, is_writes) in find_quorlin_functions(&lines) {
            if !is_writes { continue; }

            let fn_body = extract_function_body(&lines, fn_start);

            let changes_state = fn_body.iter().any(|(_, l)| quorlin_state_assign_target(l).is_some());
            let emits = fn_body.iter().any(|(_, l)| l.trim().starts_with("emit "));

            if changes_state && !emits {
                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::Other("MissingEvent".into()),
                    severity: FindingSeverity::Low,
                    description: format!(
                        "`writes` function `{}` modifies state but emits no event, even \
                         though the contract declares events. Indexers will miss this \
                         state transition.",
                        fn_name
                    ),
                    affected_lines: vec![LineRange {
                        start: fn_start as u32 + 1,
                        end: fn_start as u32 + 1,
                    }],
                    affected_functions: vec![fn_name],
                    confidence: 0.60,
                    action_hint: Some("write_state".into()),
                    fix_hint: Some(FixHint {
                        patched: "emit StateChanged(caller, new_value);".into(),
                        explanation: "Emit an event for every externally-visible state change.".into(),
                    }),
                });
            }
        }

        matches
    }
}

/// QL-WA-01: Wrapping arithmetic used (`+%` `-%` `*%`) (Medium)
struct QuorlinWrappingMathRule;

impl DetectionRule for QuorlinWrappingMathRule {
    fn check_name(&self) -> &str { "QL-WA-01" }

    fn detect(&self, source: &str) -> Vec<RuleMatch> {
        let mut matches = Vec::new();
        let lines: Vec<&str> = source.lines().collect();

        const WRAP_OPS: &[&str] = &["+%", "-%", "*%"];

        for (i, line) in lines.iter().enumerate() {
            if line.trim().starts_with("//") { continue; }

            let found_op = WRAP_OPS.iter().find(|op| line.contains(**op));
            let Some(&op) = found_op else { continue };

            let fn_name = find_quorlin_enclosing_fn(&lines, i)
                .unwrap_or_else(|| "<unknown>".into());

            matches.push(RuleMatch {
                check_name: self.check_name().into(),
                vuln_class: VulnClass::ArithmeticOverflow,
                severity: FindingSeverity::Medium,
                description: format!(
                    "Wrapping arithmetic operator `{}` in `{}`. Unlike Quorlin's default \
                     checked operators (which trap), this wraps silently — verify the \
                     wrap-around is intentional for financial values.",
                    op, fn_name
                ),
                affected_lines: vec![LineRange {
                    start: i as u32 + 1,
                    end: i as u32 + 1,
                }],
                affected_functions: vec![fn_name],
                confidence: 0.55,
                action_hint: Some("write_state".into()),
                fix_hint: Some(FixHint {
                    patched: "// Replace `a +% b` with checked `a + b` (traps on overflow)\n\
                              // or add an explicit bound: require a + b >= a, \"overflow\";".into(),
                    explanation: "Prefer Quorlin's checked operators for balances; reserve wrapping ops for non-financial bit manipulation.".into(),
                }),
            });
        }

        matches
    }
}

fn find_functions(lines: &[&str]) -> Vec<(usize, String)> {
    let mut results = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if line.contains("function ") && (line.contains("public") || line.contains("external") ||
            line.contains("internal") || line.contains("private")) {
            let name = line.split("function ")
                .nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|| format!("fn_at_line_{}", i + 1));
            results.push((i, name));
        }
    }
    results
}

fn extract_function_body<'a>(lines: &[&'a str], fn_start: usize) -> Vec<(usize, &'a str)> {
    let mut depth = 0i32;
    let mut started = false;
    let mut body = Vec::new();

    for (i, line) in lines.iter().enumerate().skip(fn_start) {
        for ch in line.chars() {
            if ch == '{' { depth += 1; started = true; }
            if ch == '}' { depth -= 1; }
        }

        body.push((i, *line));

        if started && depth <= 0 { break; }
    }

    body
}

fn find_enclosing_function(lines: &[&str], line_idx: usize) -> Option<String> {
    for line in lines[..=line_idx].iter().rev() {
        if line.contains("function ") {
            return line.split("function ")
                .nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string());
        }
    }
    None
}

fn find_rust_function(lines: &[&str], line_idx: usize) -> Option<String> {
    for line in lines[..=line_idx].iter().rev() {
        let trimmed = line.trim();
        if (trimmed.starts_with("pub fn ") || trimmed.starts_with("fn ") ||
            trimmed.starts_with("pub(crate) fn ") || trimmed.starts_with("pub async fn ") ||
            trimmed.starts_with("async fn ")) && trimmed.contains('(') {
            return trimmed.split("fn ")
                .nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string());
        }
    }
    None
}

fn find_move_function(lines: &[&str], line_idx: usize) -> Option<String> {
    for line in lines[..=line_idx].iter().rev() {
        let trimmed = line.trim();
        if (trimmed.starts_with("public fun ") || trimmed.starts_with("fun ") ||
            trimmed.starts_with("public entry fun ")) && trimmed.contains('(') {
            return trimmed.split("fun ")
                .nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string());
        }
    }
    None
}

fn find_quorlin_functions(lines: &[&str]) -> Vec<(usize, String, bool)> {
    let mut results = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        let is_writes = t.starts_with("writes ");
        let is_reads = t.starts_with("reads ");
        if !is_writes && !is_reads { continue; }

        let rest = t.split_once(' ').map(|(_, r)| r).unwrap_or("");

        if let Some(tok) = rest.split_whitespace().find(|w| w.contains('(')) {
            let name = tok.split('(').next().unwrap_or("").trim().to_string();
            if !name.is_empty() {
                results.push((i, name, is_writes));
            }
        }
    }

    results
}

fn quorlin_state_assign_target(line: &str) -> Option<String> {
    let t = line.trim();

    if t.starts_with("let ") || t.starts_with("require ") ||
        t.starts_with("require(") || t.starts_with("emit ") ||
        t.starts_with("//") || t.starts_with("return ") {
        return None;
    }

    let (lhs, _) = t.split_once('=')?;
    let lhs = lhs.trim();

    if lhs.is_empty() || lhs.contains('(') { return None; }

    if lhs.contains(' ') && !lhs.contains('[') {
        return None;
    }

    Some(lhs.to_string())
}

fn find_quorlin_enclosing_fn(lines: &[&str], line_idx: usize) -> Option<String> {
    for line in lines[..=line_idx].iter().rev() {
        let t = line.trim();
        if t.starts_with("writes ") || t.starts_with("reads ") {
            let rest = t.split_once(' ').map(|(_, r)| r).unwrap_or("");
            if let Some(tok) = rest.split_whitespace().find(|w| w.contains('(')) {
                let name = tok.split('(').next().unwrap_or("").trim();
                if !name.is_empty() {
                    return Some(name.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_all(source: &str, language: ContractLanguage) -> Vec<RuleMatch> {
        let mut all = Vec::new();
        for rule in rules_for(&language) {
            all.extend(rule.detect(source));
        }
        all
    }

    fn has_check(matches: &[RuleMatch], check: &str) -> bool {
        matches.iter().any(|m| m.check_name == check)
    }

    const VULNERABLE_QL: &str = r#"
contract VulnerableVault {
    address owner;
    map<address, number> balances;

    constructor { owner = caller; }

    writes setOwner(address newOwner) {
        owner = newOwner;
    }

    writes truth deposit(address to, number amount) {
        balances[to] = balances[to] + amount;
        return yes;
    }
}
"#;

    const CEI_QL: &str = r#"
contract Cei {
    address owner;
    map<address, number> balances;
    event Transfer(address indexed from, address indexed to, number amount);

    constructor { owner = caller; }

    writes truth withdraw(address token, number amount) {
        require balances[caller] >= amount, "insufficient";
        IERC20 t = IERC20(token);
        truth ok = t.transfer(caller, amount);
        require ok, "failed";
        balances[caller] = balances[caller] - amount;
        return yes;
    }
}
"#;

    #[test]
    fn quorlin_ac01_unrestricted_write() {
        let m = detect_all(VULNERABLE_QL, ContractLanguage::Quorlin);
        assert!(has_check(&m, "QL-AC-01"), "expected QL-AC-01, got: {:?}",
            m.iter().map(|x| x.check_name.as_str()).collect::<Vec<_>>());
    }

    #[test]
    fn quorlin_ac02_privileged_write() {
        let m = detect_all(VULNERABLE_QL, ContractLanguage::Quorlin);
        assert!(has_check(&m, "QL-AC-02"), "expected QL-AC-02");
    }

    #[test]
    fn quorlin_ac03_single_step_ownership() {
        let m = detect_all(VULNERABLE_QL, ContractLanguage::Quorlin);
        assert!(has_check(&m, "QL-AC-03"), "expected QL-AC-03");
    }

    #[test]
    fn quorlin_iv01_missing_nobody_check() {
        let m = detect_all(VULNERABLE_QL, ContractLanguage::Quorlin);
        assert!(has_check(&m, "QL-IV-01"), "expected QL-IV-01");
    }

    #[test]
    fn quorlin_iv03_missing_amount_check() {
        let m = detect_all(VULNERABLE_QL, ContractLanguage::Quorlin);
        assert!(has_check(&m, "QL-IV-03"), "expected QL-IV-03");
    }

    #[test]
    fn quorlin_re01_cei_violation() {
        let m = detect_all(CEI_QL, ContractLanguage::Quorlin);
        assert!(has_check(&m, "QL-RE-01"), "expected QL-RE-01, got: {:?}",
            m.iter().map(|x| x.check_name.as_str()).collect::<Vec<_>>());
    }

    #[test]
    fn quorlin_re03_call_result_checked() {
        let m = detect_all(CEI_QL, ContractLanguage::Quorlin);
        assert!(!has_check(&m, "QL-RE-03"), "false positive on checked call");
    }

    #[test]
    fn quorlin_wrapping_math() {
        let src = "contract W { number n; writes f() { n = n +% 1; } }";
        let m = detect_all(src, ContractLanguage::Quorlin);
        assert!(has_check(&m, "QL-WA-01"), "expected QL-WA-01");
    }

    #[test]
    fn quorlin_origin_auth() {
        let src = "contract O {\n    address owner;\n    constructor { owner = caller; }\n    writes f() {\n        require origin == owner, \"auth\";\n    }\n}\n";
        let m = detect_all(src, ContractLanguage::Quorlin);
        assert!(has_check(&m, "QL-AC-04"), "expected QL-AC-04, got: {:?}",
            m.iter().map(|x| x.check_name.as_str()).collect::<Vec<_>>());
    }

    const SOLIDITY_SIG: &str = r#"
pragma solidity ^0.8.0;
contract Vote {
    function verify(address voter, bytes32 msgHash, bytes32 sig) public returns (bool) {
        address signer = ecrecover(msgHash, v, r, s);
        return signer == voter;
    }
}
"#;

    #[test]
    fn solidity_signature_replay() {
        let m = detect_all(SOLIDITY_SIG, ContractLanguage::Solidity);
        assert!(has_check(&m, "signature-replay"), "expected signature-replay, got: {:?}",
            m.iter().map(|x| x.check_name.as_str()).collect::<Vec<_>>());
    }

    #[test]
    fn solidity_unprotected_mint() {
        let src = r#"
contract T {
    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}
"#;
        let m = detect_all(src, ContractLanguage::Solidity);
        assert!(has_check(&m, "unprotected-mint"), "expected unprotected-mint");
    }

    #[test]
    fn solidity_protected_mint_clean() {
        let src = r#"
contract T {
    function mint(address to, uint256 amount) public onlyRole(MINTER_ROLE) {
        require(to != address(0), "zero");
        _mint(to, amount);
    }
}
"#;
        let m = detect_all(src, ContractLanguage::Solidity);
        assert!(!has_check(&m, "unprotected-mint"), "false positive on protected mint");
    }

    const RUST_REMAINING: &str = r#"
#[derive(Accounts)]
pub struct Split<'info> {
    pub authority: Signer<'info>,
}

pub fn split(ctx: Context<Split>, amount: u64) -> Result<()> {
    for acct in ctx.remaining_accounts {
        let lamports = acct.lamports();
    }
    Ok(())
}
"#;

    #[test]
    fn rust_remaining_accounts_unvalidated() {
        let m = detect_all(RUST_REMAINING, ContractLanguage::Rust);
        assert!(has_check(&m, "unvalidated-remaining-accounts"),
            "expected unvalidated-remaining-accounts, got: {:?}",
            m.iter().map(|x| x.check_name.as_str()).collect::<Vec<_>>());
    }

    #[test]
    fn rust_seeds_without_bump() {
        let src = r#"
#[derive(Accounts)]
pub struct Init<'info> {
    #[account(seeds = [b"vault", authority.key().as_ref()])]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}
"#;
        let m = detect_all(src, ContractLanguage::Rust);
        assert!(has_check(&m, "non-canonical-bump"), "expected non-canonical-bump");
    }

    const MOVE_ENTRY: &str = r#"
module vault::core {
    struct Vault has key { balance: u64 }

    public entry fun mint_global(amount: u64) {
        let v = borrow_global_mut<Vault>(@vault);
        v.balance = v.balance + amount;
    }
}
"#;

    #[test]
    fn move_unprotected_entry() {
        let m = detect_all(MOVE_ENTRY, ContractLanguage::Move);
        assert!(has_check(&m, "move-unprotected-entry"),
            "expected move-unprotected-entry, got: {:?}",
            m.iter().map(|x| x.check_name.as_str()).collect::<Vec<_>>());
    }

    const CAIRO_WRITE: &str = r#"
#[starknet::contract]
mod Ownable {
    #[storage]
    struct Storage { owner: ContractAddress, value: u256 }

    #[external(v0)]
    pub fn set_value(ref self: ContractState, v: u256) {
        self.value.write(v);
    }
}
"#;

    #[test]
    fn cairo_unprotected_storage_write() {
        let m = detect_all(CAIRO_WRITE, ContractLanguage::Cairo);
        assert!(has_check(&m, "cairo-unprotected-storage-write"),
            "expected cairo-unprotected-storage-write, got: {:?}",
            m.iter().map(|x| x.check_name.as_str()).collect::<Vec<_>>());
    }

    const AIKEN_SPEND: &str = r#"
validator {
  spend(datum: Option<Datum>, redeemer: Redeemer, self: OutputReference, tx: Transaction) {
    True
  }
}
"#;

    #[test]
    fn aiken_datum_hijack() {
        let m = detect_all(AIKEN_SPEND, ContractLanguage::Aiken);
        assert!(has_check(&m, "aiken-datum-hijack"),
            "expected aiken-datum-hijack, got: {:?}",
            m.iter().map(|x| x.check_name.as_str()).collect::<Vec<_>>());
    }

    #[test]
    fn aiken_missing_signatory() {
        let m = detect_all(AIKEN_SPEND, ContractLanguage::Aiken);
        assert!(has_check(&m, "aiken-missing-signatory"),
            "expected aiken-missing-signatory");
    }

    #[test]
    fn aiken_validated_spend_clean() {
        let src = r#"
validator {
  spend(datum: Option<Datum>, redeemer: Redeemer, self: OutputReference, tx: Transaction) {
    expect Some(d) = datum
    assert d.owner == tx.extra_signatories.at(0)
    expect own_value = self.value
    True
  }
}
"#;
        let m = detect_all(src, ContractLanguage::Aiken);
        assert!(!has_check(&m, "aiken-datum-hijack"),
            "false positive: datum IS validated");
        assert!(!has_check(&m, "aiken-double-satisfaction"),
            "false positive: outputs not checked / tied to self");
    }

    const COMPACT_SRC: &str = r#"
export class Vault {
  private secret: Field;
  balance: Cell<bigint>;

  @action
  async pay(tx: Transaction, amount: bigint): Promise<Transaction> {
    log(this.secret);
    this.balance.value = this.balance.value - amount;
    return tx;
  }
}
"#;

    #[test]
    fn compact_private_leak() {
        let m = detect_all(COMPACT_SRC, ContractLanguage::Compact);
        assert!(has_check(&m, "compact-private-state-leak"),
            "expected compact-private-state-leak, got: {:?}",
            m.iter().map(|x| x.check_name.as_str()).collect::<Vec<_>>());
    }

    #[test]
    fn compact_underconstrained_action() {
        let m = detect_all(COMPACT_SRC, ContractLanguage::Compact);
        assert!(has_check(&m, "compact-underconstrained-action"),
            "expected compact-underconstrained-action");
    }
}
   
