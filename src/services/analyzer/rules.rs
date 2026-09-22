use crate::models::contract::ContractLanguage;
use crate::models::finding::FindingSeverity;
use crate::models::vuln_ontology::{LineRange, VulnClass};

#[derive(Debug, Clone)]
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
    ]
}

fn rust_solana_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(MissingSignerRule),
        Box::new(PdaSeedRule),
        Box::new(RustArithmeticRule),
        Box::new(MissingOwnerCheckRule),
    ]
}

fn move_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(MoveArithmeticRule),
        Box::new(MoveAcquiresRule),
    ]
}

fn cairo_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(FeltOverflowRule),
        Box::new(CairoReentrancyRule),
    ]
}

fn aiken_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(ValidatorBypassRule),
    ]
}

fn compact_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(CompactStateLeakRule),
    ]
}

fn quorlin_rules() -> Vec<Box<dyn DetectionRule>> {
    vec![
        Box::new(QuorlinPermissionRule),
    ]
}

// ─────────────────────────────────────────────────
// Solidity rules
// ─────────────────────────────────────────────────

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
                    matches.push(RuleMatch {
                        check_name: self.check_name().into(),
                        vuln_class: VulnClass::Reentrancy,
                        severity: FindingSeverity::High,
                        description: format!(
                            "Potential reentrancy in `{}`: external call precedes state modification. \
                             An attacker can re-enter this function before state is updated.",
                            fn_name
                        ),
                        affected_lines: vec![LineRange {
                            start: fn_start as u32 + 1,
                            end: call_line + 1,
                        }],
                        affected_functions: vec![fn_name.clone()],
                        confidence: 0.85,
                        action_hint: Some("external_call".into()),
                        fix_hint: Some(FixHint {
                            patched: format!(
                                "// Move state changes before the external call in `{}`\n\
                                 // Or use the Checks-Effects-Interactions pattern\n\
                                 // Or add a ReentrancyGuard modifier",
                                fn_name
                            ),
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
                        "Unchecked return value from low-level call in `{}`. \
                         The call may silently fail.",
                        fn_name
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
                affected_functions: vec![fn_name.clone()],
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
            let fn_header = lines.get(fn_start).map(|l| *l).unwrap_or("");
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
                        matches.push(RuleMatch {
                            check_name: self.check_name().into(),
                            vuln_class: VulnClass::AccessControl,
                            severity: FindingSeverity::High,
                            description: format!(
                                "Dangerous operation `{}` in `{}` without access control. \
                                 Any address can call this function.",
                                op.trim_end_matches('('), fn_name
                            ),
                            affected_lines: vec![LineRange {
                                start: *line_no as u32 + 1,
                                end: *line_no as u32 + 1,
                            }],
                            affected_functions: vec![fn_name.clone()],
                            confidence: 0.90,
                            action_hint: Some("write_state".into()),
                            fix_hint: Some(FixHint {
                                patched: format!(
                                    "modifier onlyOwner() {{\n    require(msg.sender == owner);\n    _;\n}}\n\nfunction {}(...) public onlyOwner {{",
                                    fn_name
                                ),
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

                let fn_header = lines.get(fn_start).map(|l| *l).unwrap_or("");
                let has_protection = fn_header.contains("onlyOwner") ||
                    fn_header.contains("internal") ||
                    fn_header.contains("private");

                if has_protection { continue; }

                matches.push(RuleMatch {
                    check_name: self.check_name().into(),
                    vuln_class: VulnClass::DelegateCallInjection,
                    severity: FindingSeverity::High,
                    description: format!(
                        "Unprotected `delegatecall` in public function `{}`. \
                         An attacker could execute arbitrary code in this contract's context.",
                        fn_name
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

// ─────────────────────────────────────────────────
// Rust / Solana rules
// ─────────────────────────────────────────────────

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

            let seed_line = lines[i.saturating_sub(3)..=i].join(" ");
            let has_unique_seed = seed_line.contains("key()") ||
                seed_line.contains(".key.as_ref()") ||
                seed_line.contains("user.key()");

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

// ─────────────────────────────────────────────────
// Move rules
// ─────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────
// Cairo rules
// ─────────────────────────────────────────────────

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
                        end: (i + 10).min(lines.len() - 1) as u32 + 1,
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

// ─────────────────────────────────────────────────
// Aiken (Cardano) rules
// ─────────────────────────────────────────────────

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

            let body_range = lines[i..lines.len().min(i + 30)].join("\n");
            let always_true = body_range.contains("True") &&
                !body_range.contains("False") &&
                !body_range.contains("fail") &&
                !body_range.contains("expect");

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
                        end: (i + 5).min(lines.len() - 1) as u32 + 1,
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

// ─────────────────────────────────────────────────
// Compact (Midnight) rules
// ─────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────
// Quorlin (Kortana) rules
// ─────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────

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

fn extract_function_body<'a>(lines: &'a [&'a str], fn_start: usize) -> Vec<(usize, &'a str)> {
    let mut depth = 0i32;
    let mut started = false;
    let mut body = Vec::new();

    for i in fn_start..lines.len() {
        let line = lines[i];
        for ch in line.chars() {
            if ch == '{' { depth += 1; started = true; }
            if ch == '}' { depth -= 1; }
        }

        body.push((i, line));

        if started && depth <= 0 { break; }
    }

    body
}

fn find_enclosing_function(lines: &[&str], line_idx: usize) -> Option<String> {
    for i in (0..=line_idx).rev() {
        if lines[i].contains("function ") {
            return lines[i].split("function ")
                .nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string());
        }
    }
    None
}

fn find_rust_function(lines: &[&str], line_idx: usize) -> Option<String> {
    for i in (0..=line_idx).rev() {
        let line = lines[i].trim();
        if (line.starts_with("pub fn ") || line.starts_with("fn ") ||
            line.starts_with("pub(crate) fn ") || line.starts_with("pub async fn ") ||
            line.starts_with("async fn ")) && line.contains('(') {
            return line.split("fn ")
                .nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string());
        }
    }
    None
}

fn find_move_function(lines: &[&str], line_idx: usize) -> Option<String> {
    for i in (0..=line_idx).rev() {
        let line = lines[i].trim();
        if (line.starts_with("public fun ") || line.starts_with("fun ") ||
            line.starts_with("public entry fun ")) && line.contains('(') {
            return line.split("fun ")
                .nth(1)
                .and_then(|s| s.split('(').next())
                .map(|s| s.trim().to_string());
        }
    }
    None
}
