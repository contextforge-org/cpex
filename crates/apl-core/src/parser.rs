// Location: ./crates/apl-core/src/parser.rs
// Copyright 2025
// SPDX-License-Identifier: Apache-2.0
// Authors: Teryl Taylor
//
// APL parser — DSL string → IR, and YAML config → HashMap<route_key, CompiledRoute>.
//
// Runs once at config load. The IR it produces is what the evaluator walks
// at request time; the parser is never on the hot path.
//
// Grammar anchored in apl-dsl-spec.md §2 (predicates) / §3 (rules) / §8 (EBNF).
// YAML shape anchored in apl-design.md §5 (`routes:` as map keyed by route_key).
//
// Step 5a scope:
//   ✓ Predicate grammar: identifiers, literals, comparisons, contains,
//     & | ! parens, require(...)
//   ✓ Actions: deny / allow / (default deny on missing)
//   ✓ YAML top-level routes: keyed map, policy: / post_policy: blocks
//   ✗ Steps (cedar:(), opa(), plugin(), taint()) — rejected with clear errors
//   ✗ Pipe chains in args:/result: — fields parsed, values stashed as opaque
//   ✗ `in` / `not in` / `exists()` — need IR variants first; rejected
//   ✗ Multi-effect do: lists, sequential:/parallel: blocks — rejected

use std::collections::HashMap;

use serde::Deserialize;
use thiserror::Error;

use crate::pipeline::{FieldRule, Pipeline, ScanKind, Stage, TaintScope, TypeCheck};
use crate::rules::{Action, CompareOp, CompiledRoute, Condition, Expression, Literal, Rule};
use crate::step::{PdpCall, PdpDialect, Step};

// =====================================================================
// Errors
// =====================================================================

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("rule '{rule}': {msg}")]
    Rule { rule: String, msg: String },

    #[error("unsupported step `{kind}` in rule '{rule}' — defer to step 5b")]
    UnsupportedStep { rule: String, kind: String },

    #[error("predicate '{predicate}': {msg}")]
    Predicate { predicate: String, msg: String },
}

// =====================================================================
// Lexer
// =====================================================================

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),     // dotted: subject.id, role.hr, authenticated
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),
    BoolLit(bool),
    Eq,                // ==
    NotEq,             // !=
    Gt,                // >
    GtEq,              // >=
    Lt,                // <
    LtEq,              // <=
    And,               // &  (must have surrounding spaces — caller enforces)
    Or,                // |
    Not,               // !
    LParen,
    RParen,
    Comma,
    Contains,          // keyword
    Require,           // keyword
    Exists,            // keyword
    In,                // keyword — set membership operator
}

struct Lexer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self { src, bytes: src.as_bytes(), pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b.is_ascii_whitespace() { self.pos += 1; } else { break; }
        }
    }

    fn tokenize_all(&mut self) -> Result<Vec<Tok>, ParseError> {
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            let Some(b) = self.peek() else { return Ok(out); };

            let tok = match b {
                b'(' => { self.pos += 1; Tok::LParen }
                b')' => { self.pos += 1; Tok::RParen }
                b',' => { self.pos += 1; Tok::Comma }
                b'&' => { self.pos += 1; Tok::And }
                b'|' => { self.pos += 1; Tok::Or }
                b'=' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') {
                        self.pos += 1; Tok::Eq
                    } else {
                        return Err(self.err("expected `==`, saw `=`"));
                    }
                }
                b'!' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') {
                        self.pos += 1; Tok::NotEq
                    } else {
                        Tok::Not
                    }
                }
                b'>' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') { self.pos += 1; Tok::GtEq } else { Tok::Gt }
                }
                b'<' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') { self.pos += 1; Tok::LtEq } else { Tok::Lt }
                }
                b'"' | b'\'' => self.lex_string(b)?,
                b'-' | b'0'..=b'9' => self.lex_number()?,
                b if is_ident_start(b) => self.lex_ident_or_keyword(),
                _ => return Err(self.err(&format!("unexpected char `{}`", b as char))),
            };
            out.push(tok);
        }
    }

    fn lex_string(&mut self, quote: u8) -> Result<Tok, ParseError> {
        self.bump(); // opening quote
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b == quote { break; }
            self.pos += 1;
        }
        if self.peek() != Some(quote) {
            return Err(self.err("unterminated string literal"));
        }
        let s = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| self.err("non-utf8 in string literal"))?
            .to_string();
        self.bump(); // closing quote
        Ok(Tok::StringLit(s))
    }

    fn lex_number(&mut self) -> Result<Tok, ParseError> {
        let start = self.pos;
        if self.peek() == Some(b'-') { self.pos += 1; }
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() { self.pos += 1; } else { break; }
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            while let Some(b) = self.peek() {
                if b.is_ascii_digit() { self.pos += 1; } else { break; }
            }
        }
        let text = &self.src[start..self.pos];
        if is_float {
            text.parse::<f64>().map(Tok::FloatLit)
                .map_err(|_| self.err(&format!("bad float `{}`", text)))
        } else {
            text.parse::<i64>().map(Tok::IntLit)
                .map_err(|_| self.err(&format!("bad int `{}`", text)))
        }
    }

    fn lex_ident_or_keyword(&mut self) -> Tok {
        let start = self.pos;
        while let Some(b) = self.peek() {
            if is_ident_cont(b) { self.pos += 1; } else { break; }
        }
        let s = &self.src[start..self.pos];
        match s {
            "true" => Tok::BoolLit(true),
            "false" => Tok::BoolLit(false),
            "contains" => Tok::Contains,
            "require" => Tok::Require,
            "exists" => Tok::Exists,
            "in" => Tok::In,
            // "not" is NOT a keyword — it only appears in the `not in`
            // phrase. The parser handles that as an Ident("not") + Tok::In
            // sequence in parse_identifier_predicate.
            _ => Tok::Ident(s.to_string()),
        }
    }

    fn err(&self, msg: &str) -> ParseError {
        ParseError::Predicate {
            predicate: self.src.to_string(),
            msg: format!("at byte {}: {}", self.pos, msg),
        }
    }
}

fn is_ident_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn is_ident_cont(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'.'
}

// =====================================================================
// Predicate parser (Pratt-style; precedence () > ! > & > |)
// =====================================================================

struct PredParser<'a> {
    src: &'a str,
    toks: Vec<Tok>,
    pos: usize,
}

impl<'a> PredParser<'a> {
    fn parse(src: &'a str) -> Result<Expression, ParseError> {
        let toks = Lexer::new(src).tokenize_all()?;
        let mut p = Self { src, toks, pos: 0 };
        let expr = p.parse_or()?;
        if p.pos < p.toks.len() {
            return Err(p.err(&format!("trailing tokens after expression: {:?}", &p.toks[p.pos..])));
        }
        Ok(expr)
    }

    fn peek(&self) -> Option<&Tok> { self.toks.get(self.pos) }
    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned()?;
        self.pos += 1;
        Some(t)
    }
    fn err(&self, msg: &str) -> ParseError {
        ParseError::Predicate {
            predicate: self.src.to_string(),
            msg: msg.to_string(),
        }
    }

    fn parse_or(&mut self) -> Result<Expression, ParseError> {
        let mut parts = vec![self.parse_and()?];
        while matches!(self.peek(), Some(Tok::Or)) {
            self.bump();
            parts.push(self.parse_and()?);
        }
        Ok(if parts.len() == 1 { parts.pop().unwrap() } else { Expression::Or(parts) })
    }

    fn parse_and(&mut self) -> Result<Expression, ParseError> {
        let mut parts = vec![self.parse_unary()?];
        while matches!(self.peek(), Some(Tok::And)) {
            self.bump();
            parts.push(self.parse_unary()?);
        }
        Ok(if parts.len() == 1 { parts.pop().unwrap() } else { Expression::And(parts) })
    }

    fn parse_unary(&mut self) -> Result<Expression, ParseError> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.bump();
            let inner = self.parse_unary()?;
            return Ok(Expression::Not(Box::new(inner)));
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> Result<Expression, ParseError> {
        match self.peek() {
            Some(Tok::LParen) => {
                self.bump();
                let inner = self.parse_or()?;
                match self.bump() {
                    Some(Tok::RParen) => Ok(inner),
                    _ => Err(self.err("expected `)`")),
                }
            }
            // `require(...)` is a rule-level shorthand per DSL §8 grammar
            // (`rule = require_call | predicate ...`), not a sub-predicate.
            // Trying to nest it inside `&` / `|` is a grammar error.
            Some(Tok::Require) => Err(self.err(
                "`require(...)` is a rule-level shorthand, not a sub-predicate \
                 — use `&` / `|` / `!` over bare identifiers instead",
            )),
            Some(Tok::Exists) => self.parse_exists(),
            Some(Tok::Ident(_)) => self.parse_identifier_predicate(),
            other => Err(self.err(&format!("expected atom, got {:?}", other))),
        }
    }

    /// `exists(<identifier>)` — DSL §2.2. Returns true if the key is present
    /// in the AttributeBag, regardless of value (distinct from truthiness).
    fn parse_exists(&mut self) -> Result<Expression, ParseError> {
        self.bump(); // exists
        match self.bump() {
            Some(Tok::LParen) => {}
            _ => return Err(self.err("expected `(` after `exists`")),
        }
        let key = match self.bump() {
            Some(Tok::Ident(s)) => s,
            other => return Err(self.err(&format!(
                "exists(...) expects an attribute key, got {:?}", other,
            ))),
        };
        match self.bump() {
            Some(Tok::RParen) => {}
            other => return Err(self.err(&format!(
                "expected `)` after exists() argument, got {:?}", other,
            ))),
        }
        Ok(Expression::Condition(Condition::Exists { key }))
    }

    /// Parse a predicate that begins with an identifier:
    ///   - bare identifier:    `authenticated`  → IsTrue
    ///   - comparison:         `delegation.depth > 2`
    ///   - contains:           `session.labels contains "PII"`
    ///   - set membership:     `subject.type in allowed_types`
    ///   - set non-membership: `subject.type not in blocked_types`
    fn parse_identifier_predicate(&mut self) -> Result<Expression, ParseError> {
        let key = match self.bump() {
            Some(Tok::Ident(s)) => s,
            _ => unreachable!("parse_atom dispatched here"),
        };

        // `in` and `not in` — two-key set membership (DSL §2.4).
        if matches!(self.peek(), Some(Tok::In)) {
            self.bump();
            return self.finish_in_set(key, false);
        }
        // `not in` shows up as Ident("not") + Tok::In. Treat that as a
        // grammar phrase here; bare `not` outside this context is not a
        // DSL keyword (use `!` for predicate negation).
        if let Some(Tok::Ident(maybe_not)) = self.peek() {
            if maybe_not == "not" {
                let saved_pos = self.pos;
                self.bump(); // consume "not"
                if matches!(self.peek(), Some(Tok::In)) {
                    self.bump();
                    return self.finish_in_set(key, true);
                }
                // Not "not in" — rewind so the downstream error reports
                // the trailing-ident properly.
                self.pos = saved_pos;
            }
        }

        let op = match self.peek() {
            Some(Tok::Eq) => Some(CompareOp::Eq),
            Some(Tok::NotEq) => Some(CompareOp::NotEq),
            Some(Tok::Gt) => Some(CompareOp::Gt),
            Some(Tok::GtEq) => Some(CompareOp::GtEq),
            Some(Tok::Lt) => Some(CompareOp::Lt),
            Some(Tok::LtEq) => Some(CompareOp::LtEq),
            Some(Tok::Contains) => Some(CompareOp::Contains),
            _ => None,
        };

        let Some(op) = op else {
            // Bare identifier.
            return Ok(Expression::Condition(Condition::IsTrue { key }));
        };
        self.bump();

        let value = match self.bump() {
            Some(Tok::StringLit(s)) => Literal::String(s),
            Some(Tok::IntLit(i)) => Literal::Int(i),
            Some(Tok::FloatLit(f)) => Literal::Float(f),
            Some(Tok::BoolLit(b)) => Literal::Bool(b),
            Some(Tok::Ident(_)) => {
                return Err(self.err(
                    "RHS-as-identifier on comparison operators not supported — \
                     for set membership use `value_key in set_key`",
                ));
            }
            other => return Err(self.err(&format!("expected literal RHS, got {:?}", other))),
        };

        Ok(Expression::Condition(Condition::Comparison { key, op, value }))
    }

    fn finish_in_set(&mut self, value_key: String, negate: bool) -> Result<Expression, ParseError> {
        let set_key = match self.bump() {
            Some(Tok::Ident(s)) => s,
            other => return Err(self.err(&format!(
                "expected set-attribute identifier after `{}in`, got {:?}",
                if negate { "not " } else { "" },
                other,
            ))),
        };
        Ok(Expression::Condition(Condition::InSet { value_key, set_key, negate }))
    }
}

/// Parse a predicate string into the IR. Public for tests + step-5b use.
pub fn parse_predicate(src: &str) -> Result<Expression, ParseError> {
    PredParser::parse(src.trim())
}

// =====================================================================
// Rule parser
// =====================================================================

/// Parse a single rule line into a `Rule`.
///
/// Accepted forms (DSL §3.2):
///   1. `"require(...)"`           →  rule-level shorthand, desugars to
///                                    `when: <negated condition> do: deny`
///                                    per DSL §8.1
///   2. `"<predicate>: <action>"`  →  Rule { condition, action }
///   3. `"<predicate>"`            →  Rule { condition, action: Deny } (default)
///   4. `"<action>"` (action only) →  treated as form 3 (always-true predicate)
///
/// **Step kinds** (`plugin(...)`, `taint(...)`, `cedar:`, `opa(...)` etc.)
/// are handled by `parse_step`, not here. This function specifically parses
/// predicate-and-action rules; callers that don't know which they have
/// should use `parse_step` instead.
pub fn parse_rule(line: &str, source: &str) -> Result<Rule, ParseError> {
    let trimmed = line.trim();

    // require(...) shorthand — special-cased because it desugars to a
    // negated predicate + Deny action, and the spec grammar (§8) puts it
    // as a top-level rule alternative, not a sub-predicate.
    if is_require_call(trimmed) {
        let condition = parse_require_rule(trimmed)?;
        return Ok(Rule {
            condition,
            action: Action::Deny { reason: None },
            source: source.to_string(),
        });
    }

    // Step kinds shouldn't end up here. If they do, the caller used the
    // wrong entry point — point them at parse_step.
    if let Some(kind) = detect_step_kind(trimmed) {
        return Err(ParseError::UnsupportedStep {
            rule: trimmed.to_string(),
            kind: format!("{} (use parse_step for step kinds)", kind),
        });
    }

    let (predicate_str, action) = match split_predicate_action(trimmed) {
        Some((p, a)) => (p, parse_action(a, trimmed)?),
        None => {
            // No `:` — bare action (unconditional) or bare predicate (default deny).
            if let Some(action) = try_bare_action(trimmed) {
                return Ok(Rule {
                    condition: Expression::Always,
                    action,
                    source: source.to_string(),
                });
            }
            (trimmed, Action::Deny { reason: None }) // DSL §2 default
        }
    };

    let condition = parse_predicate(predicate_str)
        .map_err(|e| ParseError::Rule {
            rule: trimmed.to_string(),
            msg: format!("{}", e),
        })?;

    Ok(Rule { condition, action, source: source.to_string() })
}

fn is_require_call(s: &str) -> bool {
    s.trim_start().starts_with("require(")
}

/// Parse `require(a)` / `require(a, b, ...)` / `require(a | b | ...)` and
/// return the desugared "when" expression per DSL §8.1:
///
///   require(X)             →  IsFalse(X)
///   require(X, Y, ...)     →  Or([IsFalse(X), IsFalse(Y), ...])   (deny if any falsy)
///   require(X | Y | ...)   →  And([IsFalse(X), IsFalse(Y), ...])  (deny if all falsy)
///
/// Caller wraps with `Action::Deny`.
fn parse_require_rule(line: &str) -> Result<Expression, ParseError> {
    let toks = Lexer::new(line).tokenize_all()?;
    let mut iter = toks.into_iter().peekable();

    let bad = |msg: &str| ParseError::Rule {
        rule: line.to_string(),
        msg: msg.to_string(),
    };

    match iter.next() {
        Some(Tok::Require) => {}
        _ => return Err(bad("expected `require`")),
    }
    match iter.next() {
        Some(Tok::LParen) => {}
        _ => return Err(bad("expected `(` after `require`")),
    }

    let mut keys = Vec::new();
    let mut sep: Option<Tok> = None;

    match iter.next() {
        Some(Tok::Ident(s)) => keys.push(s),
        _ => return Err(bad("expected identifier inside `require(...)`")),
    }

    loop {
        match iter.next() {
            Some(Tok::RParen) => break,
            Some(t @ Tok::Comma) | Some(t @ Tok::Or) => {
                match &sep {
                    None => sep = Some(t),
                    Some(prev) if std::mem::discriminant(prev) == std::mem::discriminant(&t) => {}
                    _ => return Err(bad(
                        "require(...) cannot mix `,` (AND) and `|` (OR) — use one or the other",
                    )),
                }
                match iter.next() {
                    Some(Tok::Ident(s)) => keys.push(s),
                    _ => return Err(bad("expected identifier after `,` or `|` in require(...)")),
                }
            }
            Some(other) => return Err(bad(&format!(
                "expected `,`, `|`, or `)` in require(...), got {:?}", other,
            ))),
            None => return Err(bad("unexpected end of require(...) — missing `)`")),
        }
    }

    if iter.peek().is_some() {
        return Err(bad("trailing tokens after `require(...)` — require is a complete rule"));
    }

    let falses: Vec<Expression> = keys
        .into_iter()
        .map(|k| Expression::Condition(Condition::IsFalse { key: k }))
        .collect();
    if falses.len() == 1 {
        return Ok(falses.into_iter().next().unwrap());
    }
    Ok(match sep {
        Some(Tok::Or) => Expression::And(falses),    // require(X | Y) → !X & !Y
        _ => Expression::Or(falses),                 // require(X, Y)  → !X | !Y
    })
}

/// Detect `taint(...)` / `plugin(...)` / `cedar:` / `opa(` / `authzen(` / `nemo(`.
fn detect_step_kind(s: &str) -> Option<&'static str> {
    let s = s.trim_start();
    for prefix in ["taint(", "plugin(", "cedar:", "opa(", "authzen(", "nemo(", "sequential:", "parallel:"] {
        if s.starts_with(prefix) {
            return Some(prefix.trim_end_matches('(').trim_end_matches(':'));
        }
    }
    None
}

/// Split on the *last* unescaped `:` that's outside quotes and parens — this
/// is the predicate/action separator. The DSL doesn't escape colons, and `:`
/// doesn't appear in our predicate grammar, but quotes and parens can contain
/// arbitrary text.
fn split_predicate_action(s: &str) -> Option<(&str, &str)> {
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut in_quote: Option<u8> = None;
    let mut last_colon: Option<usize> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match (in_quote, b) {
            (Some(q), c) if c == q => in_quote = None,
            (Some(_), _) => {}
            (None, b'"') | (None, b'\'') => in_quote = Some(b),
            (None, b'(') => depth += 1,
            (None, b')') => depth -= 1,
            (None, b':') if depth == 0 => last_colon = Some(i),
            _ => {}
        }
    }
    last_colon.map(|i| (s[..i].trim(), s[i + 1..].trim()))
}

fn parse_action(s: &str, rule: &str) -> Result<Action, ParseError> {
    match s.trim() {
        "deny" => Ok(Action::Deny { reason: None }),
        "allow" => Ok(Action::Allow),
        other => {
            // Be specific about why — common mistake will be `deny "reason"`.
            Err(ParseError::Rule {
                rule: rule.to_string(),
                msg: format!(
                    "unsupported action `{}` — only `deny` and `allow` in v1 (reasons come from PDP responses, not the DSL)",
                    other
                ),
            })
        }
    }
}

fn try_bare_action(s: &str) -> Option<Action> {
    match s.trim() {
        "deny" => Some(Action::Deny { reason: None }),
        "allow" => Some(Action::Allow),
        _ => None,
    }
}

// =====================================================================
// Step parser (policy: / post_policy: entries — supports steps + rules)
// =====================================================================

/// Parse a single YAML entry from a `policy:` / `post_policy:` list.
///
/// Two YAML shapes (DSL §3.2 + §7):
/// - **String entry** — a rule line, taint effect, or plugin call.
///   - `"require(authenticated)"` → `Step::Rule`
///   - `"delegation.depth > 2: deny"` → `Step::Rule`
///   - `"plugin(rate_limiter)"` → `Step::Plugin`
///   - `"taint(PII, session)"` → `Step::Taint`
/// - **Map entry** (single-key map) — PDP call with optional reactions.
///   - `cedar: { action: read, resource: e, on_deny: [...] }` → `Step::Pdp`
///   - `opa("path"): { on_deny: [...] }` → `Step::Pdp`
pub fn parse_step(value: &serde_yaml::Value, source: &str) -> Result<Step, ParseError> {
    match value {
        serde_yaml::Value::String(s) => parse_step_string(s, source),
        serde_yaml::Value::Mapping(m) => parse_step_map(m, source),
        other => Err(ParseError::Rule {
            rule: format!("{:?}", other),
            msg: "step must be a string or a single-key map".into(),
        }),
    }
}

fn parse_step_string(line: &str, source: &str) -> Result<Step, ParseError> {
    let trimmed = line.trim();

    // taint(...) — emit as Step::Taint, reusing the pipeline parser's logic
    // so the shape stays consistent with field-level taint.
    if trimmed.starts_with("taint(") {
        let inside = extract_call_args(trimmed, "taint")
            .ok_or_else(|| ParseError::Rule {
                rule: trimmed.to_string(),
                msg: "malformed `taint(...)`".into(),
            })?;
        let taint_stage = parse_taint(&inside, trimmed)?;
        // parse_taint produces Stage::Taint; lift to Step::Taint.
        if let Stage::Taint { label, scopes } = taint_stage {
            return Ok(Step::Taint { label, scopes });
        }
        unreachable!("parse_taint always returns Stage::Taint");
    }

    // plugin(name) — emit as Step::Plugin.
    if trimmed.starts_with("plugin(") {
        let inside = extract_call_args(trimmed, "plugin")
            .ok_or_else(|| ParseError::Rule {
                rule: trimmed.to_string(),
                msg: "malformed `plugin(...)`".into(),
            })?;
        let name = inside.trim();
        if name.is_empty() {
            return Err(ParseError::Rule {
                rule: trimmed.to_string(),
                msg: "plugin name must not be empty".into(),
            });
        }
        return Ok(Step::Plugin { name: name.to_string() });
    }

    // Otherwise fall through to the rule parser — predicate-and-action.
    let rule = parse_rule(trimmed, source)?;
    Ok(Step::Rule(rule))
}

fn parse_step_map(
    m: &serde_yaml::Mapping,
    source: &str,
) -> Result<Step, ParseError> {
    if m.len() != 1 {
        return Err(ParseError::Rule {
            rule: format!("{:?}", m),
            msg: "step map must have exactly one key (PDP call signature)".into(),
        });
    }
    let (key_val, body_val) = m.iter().next().unwrap();
    let key = key_val.as_str().ok_or_else(|| ParseError::Rule {
        rule: format!("{:?}", key_val),
        msg: "PDP step key must be a string".into(),
    })?;

    // Split the key into "dialect" + optional "(args)" portion.
    let (dialect_str, paren_args) = if let Some(open) = key.find('(') {
        let close = key.rfind(')').ok_or_else(|| ParseError::Rule {
            rule: key.to_string(),
            msg: "missing `)` in PDP call signature".into(),
        })?;
        let inside = key[open + 1..close].trim().to_string();
        (key[..open].trim(), Some(inside))
    } else {
        (key.trim(), None)
    };

    let dialect = PdpDialect::from_key(dialect_str);

    // Extract args + on_deny/on_allow.
    // Cedar: body map carries args fields directly + on_deny/on_allow.
    // Others: paren_args carries the call signature; body map is reactions only.
    let body = body_val.as_mapping().ok_or_else(|| ParseError::Rule {
        rule: format!("{:?}", body_val),
        msg: format!("`{}:` body must be a map (with on_deny / on_allow / args)", key),
    })?;

    let (args, on_deny, on_allow) = extract_pdp_body(body, paren_args.as_deref(), source)?;

    Ok(Step::Pdp {
        call: PdpCall { dialect, args },
        on_deny,
        on_allow,
    })
}

/// Split a PDP body into (args, on_deny, on_allow).
///
/// If `paren_args` is `Some`, the call's args are the string inside the
/// parens (OPA-style) and the body map only carries reactions. If `None`,
/// the body map carries both args and reactions (Cedar-style); we strip
/// the reaction keys and treat what's left as args.
fn extract_pdp_body(
    body: &serde_yaml::Mapping,
    paren_args: Option<&str>,
    source: &str,
) -> Result<(serde_yaml::Value, Vec<Step>, Vec<Step>), ParseError> {
    let mut on_deny = Vec::new();
    let mut on_allow = Vec::new();
    let mut args_map = serde_yaml::Mapping::new();

    for (k, v) in body {
        match k.as_str() {
            Some("on_deny") => {
                on_deny = parse_reaction_list(v, source, "on_deny")?;
            }
            Some("on_allow") => {
                on_allow = parse_reaction_list(v, source, "on_allow")?;
            }
            _ => {
                // Non-reaction key — part of args (Cedar-style).
                args_map.insert(k.clone(), v.clone());
            }
        }
    }

    let args = match paren_args {
        Some(s) => serde_yaml::Value::String(s.to_string()),
        None => serde_yaml::Value::Mapping(args_map),
    };

    Ok((args, on_deny, on_allow))
}

fn parse_reaction_list(
    v: &serde_yaml::Value,
    source: &str,
    which: &str,
) -> Result<Vec<Step>, ParseError> {
    let list = v.as_sequence().ok_or_else(|| ParseError::Rule {
        rule: format!("{:?}", v),
        msg: format!("`{}:` must be a list of steps", which),
    })?;
    list.iter()
        .enumerate()
        .map(|(i, entry)| parse_step(entry, &format!("{}.{}[{}]", source, which, i)))
        .collect()
}

/// Extract the args inside a call like `taint(X, Y)` or `plugin(foo)`.
/// Returns the substring between the outermost matching parens.
fn extract_call_args(line: &str, name: &str) -> Option<String> {
    let line = line.trim();
    if !line.starts_with(name) {
        return None;
    }
    let after = &line[name.len()..];
    if !after.starts_with('(') {
        return None;
    }
    // Find the matching close paren.
    let bytes = after.as_bytes();
    let mut depth = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    // Anything after the close paren is invalid.
                    if after[i + 1..].trim().is_empty() {
                        return Some(after[1..i].to_string());
                    }
                    return None;
                }
            }
            _ => {}
        }
    }
    None
}

// =====================================================================
// Pipe-chain parser (args: / result: field pipelines)
// =====================================================================

/// Parse a pipe-chain string into a `Pipeline`.
///
/// Splits on `|` (outside parens/quotes), trims each stage, parses each.
/// Empty pipelines (empty string or whitespace) are valid — they produce
/// `Pipeline { stages: vec![] }`.
pub fn parse_pipeline(src: &str) -> Result<Pipeline, ParseError> {
    let mut pipeline = Pipeline::new();
    for seg in split_top_level(src.trim(), b'|') {
        let seg = seg.trim();
        if seg.is_empty() {
            continue;
        }
        pipeline.push(parse_stage(seg)?);
    }
    Ok(pipeline)
}

/// Split `s` on `delim` at depth 0 — respects parens and quotes.
fn split_top_level(s: &str, delim: u8) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut depth: i32 = 0;
    let mut in_quote: Option<u8> = None;
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        match (in_quote, b) {
            (Some(q), c) if c == q => in_quote = None,
            (Some(_), _) => {}
            (None, b'"') | (None, b'\'') => in_quote = Some(b),
            (None, b'(') | (None, b'[') => depth += 1,
            (None, b')') | (None, b']') => depth -= 1,
            (None, c) if c == delim && depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}

fn parse_stage(src: &str) -> Result<Stage, ParseError> {
    let s = src.trim();
    let bad = |msg: &str| ParseError::Predicate {
        predicate: src.to_string(),
        msg: msg.to_string(),
    };

    // Bare range literal: starts with `-`, digit, or `..`.
    if let Some(stage) = try_parse_range(s) {
        return Ok(stage);
    }

    // Otherwise the stage starts with an identifier (keyword) optionally
    // followed by `(args)`.
    let (head, args) = split_head_args(s)
        .ok_or_else(|| bad("expected stage identifier"))?;

    match (head, args.as_deref()) {
        // ----- Bare validators / transforms / effects -----
        ("str", None) => Ok(Stage::Type(TypeCheck::Str)),
        ("int", None) => Ok(Stage::Type(TypeCheck::Int)),
        ("bool", None) => Ok(Stage::Type(TypeCheck::Bool)),
        ("float", None) => Ok(Stage::Type(TypeCheck::Float)),
        ("email", None) => Ok(Stage::Type(TypeCheck::Email)),
        ("url", None) => Ok(Stage::Type(TypeCheck::Url)),
        ("uuid", None) => Ok(Stage::Type(TypeCheck::Uuid)),
        ("redact", None) => Ok(Stage::Redact { condition: None }),
        ("omit", None) => Ok(Stage::Omit),
        ("hash", None) => Ok(Stage::Hash),
        // Scan placeholders parse as bare identifiers (DSL §4.5).
        ("pii.redact", None) => Ok(Stage::Scan { kind: ScanKind::PiiRedact }),
        ("pii.detect", None) => Ok(Stage::Scan { kind: ScanKind::PiiDetect }),
        ("injection.scan", None) => Ok(Stage::Scan { kind: ScanKind::InjectionScan }),

        // ----- Parameterized -----
        ("mask", Some(a)) => {
            let n: usize = a.trim().parse()
                .map_err(|_| bad(&format!("mask(N) expects integer, got `{}`", a)))?;
            Ok(Stage::Mask { keep_last: n })
        }
        ("redact", Some(a)) => {
            // redact(!perm.view_ssn) — argument is a predicate expression.
            let cond = parse_predicate(a).map_err(|e| ParseError::Predicate {
                predicate: src.to_string(),
                msg: format!("invalid redact() condition: {}", e),
            })?;
            Ok(Stage::Redact { condition: Some(cond) })
        }
        ("hash", Some(_)) => Err(bad("hash takes no arguments")),
        ("omit", Some(_)) => Err(bad(
            "omit takes no arguments — for conditional omit, use a policy rule predicate",
        )),
        ("len", Some(a)) => {
            let (min, max) = parse_range_inner(a)
                .ok_or_else(|| bad(&format!("len(...) expects N..M range, got `{}`", a)))?;
            let to_usize = |v: i64| -> Result<usize, ParseError> {
                if v < 0 { Err(bad("len bounds must be non-negative")) }
                else { Ok(v as usize) }
            };
            Ok(Stage::Length {
                min: min.map(to_usize).transpose()?,
                max: max.map(to_usize).transpose()?,
            })
        }
        ("enum", Some(a)) => {
            let values = split_top_level(a, b',')
                .into_iter()
                .map(|v| {
                    let t = v.trim();
                    // Allow either bare identifier or quoted string.
                    if (t.starts_with('"') && t.ends_with('"'))
                        || (t.starts_with('\'') && t.ends_with('\''))
                    {
                        t[1..t.len() - 1].to_string()
                    } else {
                        t.to_string()
                    }
                })
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>();
            if values.is_empty() {
                return Err(bad("enum() requires at least one value"));
            }
            Ok(Stage::Enum { values })
        }
        ("regex", Some(a)) => {
            let pattern = a.trim();
            let pat = if (pattern.starts_with('"') && pattern.ends_with('"'))
                || (pattern.starts_with('\'') && pattern.ends_with('\''))
            {
                pattern[1..pattern.len() - 1].to_string()
            } else {
                pattern.to_string()
            };
            Ok(Stage::Regex { pattern: pat })
        }
        ("validate", Some(a)) => Ok(Stage::Validate { name: a.trim().to_string() }),
        ("plugin", Some(a)) => Ok(Stage::Plugin { name: a.trim().to_string() }),
        ("taint", Some(a)) => parse_taint(a, src),

        (other, _) => Err(bad(&format!("unknown stage `{}`", other))),
    }
}

/// Try to parse `s` as a bare range literal: `0..100`, `..500`, `0..`, `0..1M`.
fn try_parse_range(s: &str) -> Option<Stage> {
    if !s.contains("..") {
        return None;
    }
    // Quick reject: must not start with a letter (would be a keyword).
    let first = s.as_bytes().first().copied()?;
    if first.is_ascii_alphabetic() || first == b'_' {
        return None;
    }
    let (min, max) = parse_range_inner(s)?;
    Some(Stage::Range { min, max })
}

/// Parse the inside of a range expression: `N..M`, `..M`, `N..`.
/// Returns `Some((min, max))` if shape is valid; `None` if it's not a range.
fn parse_range_inner(s: &str) -> Option<(Option<i64>, Option<i64>)> {
    let dotdot = s.find("..")?;
    let left = s[..dotdot].trim();
    let right = s[dotdot + 2..].trim();
    let min = if left.is_empty() { None } else { Some(parse_numeric_with_suffix(left)?) };
    let max = if right.is_empty() { None } else { Some(parse_numeric_with_suffix(right)?) };
    if min.is_none() && max.is_none() {
        return None; // `..` alone isn't a useful range
    }
    Some((min, max))
}

/// Parse a number with optional `k/K` (×1000) or `m/M` (×1_000_000) suffix.
fn parse_numeric_with_suffix(s: &str) -> Option<i64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_part, mult) = match s.as_bytes().last().copied()? {
        b'k' | b'K' => (&s[..s.len() - 1], 1_000_i64),
        b'm' | b'M' => (&s[..s.len() - 1], 1_000_000_i64),
        _ => (s, 1_i64),
    };
    let n: i64 = num_part.parse().ok()?;
    n.checked_mul(mult)
}

/// Split `s` (a stage form like `mask(4)`) into `(head, Some(args_inside_parens))`
/// or `(head, None)` if there are no parens.
fn split_head_args(s: &str) -> Option<(&str, Option<String>)> {
    if let Some(open) = s.find('(') {
        // Match the corresponding closing paren at depth 0.
        let bytes = s.as_bytes();
        let mut depth = 0;
        let mut close = None;
        for (i, &b) in bytes.iter().enumerate().skip(open) {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 { close = Some(i); break; }
                }
                _ => {}
            }
        }
        let close = close?;
        let head = s[..open].trim();
        if head.is_empty() { return None; }
        let args = s[open + 1..close].to_string();
        // Reject trailing garbage after the closing paren.
        if s[close + 1..].trim().is_empty() {
            Some((head, Some(args)))
        } else {
            None
        }
    } else {
        let head = s.trim();
        if head.is_empty() { None } else { Some((head, None)) }
    }
}

fn parse_taint(args: &str, src: &str) -> Result<Stage, ParseError> {
    // taint(label) | taint(label, session) | taint(label, [session, message])
    let parts = split_top_level(args, b',');
    if parts.is_empty() {
        return Err(ParseError::Predicate {
            predicate: src.to_string(),
            msg: "taint() requires at least a label".into(),
        });
    }
    let label = parts[0].trim().to_string();
    if label.is_empty() {
        return Err(ParseError::Predicate {
            predicate: src.to_string(),
            msg: "taint label must not be empty".into(),
        });
    }

    let scopes = if parts.len() == 1 {
        vec![TaintScope::Session] // default per DSL §4.6
    } else {
        let scope_arg = parts[1..].join(",");
        let scope_arg = scope_arg.trim();
        if scope_arg.starts_with('[') && scope_arg.ends_with(']') {
            split_top_level(&scope_arg[1..scope_arg.len() - 1], b',')
                .into_iter()
                .map(|s| parse_taint_scope(s.trim(), src))
                .collect::<Result<Vec<_>, _>>()?
        } else {
            vec![parse_taint_scope(scope_arg, src)?]
        }
    };

    Ok(Stage::Taint { label, scopes })
}

fn parse_taint_scope(s: &str, src: &str) -> Result<TaintScope, ParseError> {
    match s {
        "session" => Ok(TaintScope::Session),
        "message" => Ok(TaintScope::Message),
        other => Err(ParseError::Predicate {
            predicate: src.to_string(),
            msg: format!("unknown taint scope `{}` (expected `session` or `message`)", other),
        }),
    }
}

// =====================================================================
// YAML config
// =====================================================================

/// Top-level config — only the bits step 5a understands.
///
/// `policy_evaluator:`, `plugins:`, `imports:`, `global:`, `defaults:`,
/// `tags:`, `plugin_dirs:`, `plugin_settings:`, `version:` are all
/// accepted and stored opaquely; this struct deserializes leniently.
#[derive(Debug, Default, Deserialize)]
pub struct ConfigYaml {
    #[serde(default)]
    pub routes: HashMap<String, RouteYaml>,

    /// Anything else top-level goes here — picked up by later steps.
    #[serde(flatten)]
    pub other: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RouteYaml {
    /// Each entry is either a string (rule / plugin / taint) or a
    /// single-key map (PDP call with reactions). See `parse_step`.
    #[serde(default)]
    pub policy: Vec<serde_yaml::Value>,

    #[serde(default)]
    pub post_policy: Vec<serde_yaml::Value>,

    /// `args:` field → pipe-chain string. Compiled to per-field pipelines.
    #[serde(default)]
    pub args: HashMap<String, String>,

    /// `result:` field → pipe-chain string. Compiled to per-field pipelines.
    #[serde(default)]
    pub result: HashMap<String, String>,

    /// Anything else on the route (meta, taint, plugins, when) — stashed.
    #[serde(flatten)]
    pub other: HashMap<String, serde_yaml::Value>,
}

/// Compile a YAML config into a map of `route_key → CompiledRoute`.
///
/// Routes with no APL fields populated (no `policy:` / `post_policy:` /
/// `args:` / `result:`) are **omitted from the output**, per apl-design §5
/// "Routes without APL blocks fall back to legacy plugin-chain execution."
pub fn compile_config(yaml: &str) -> Result<HashMap<String, CompiledRoute>, ParseError> {
    let cfg: ConfigYaml = serde_yaml::from_str(yaml)?;
    let mut out = HashMap::with_capacity(cfg.routes.len());
    for (route_key, raw) in cfg.routes {
        if let Some(route) = compile_route(&route_key, raw)? {
            out.insert(route_key, route);
        }
    }
    Ok(out)
}

fn compile_route(route_key: &str, raw: RouteYaml) -> Result<Option<CompiledRoute>, ParseError> {
    let has_apl = !raw.policy.is_empty()
        || !raw.post_policy.is_empty()
        || !raw.args.is_empty()
        || !raw.result.is_empty();
    if !has_apl {
        return Ok(None);
    }

    let mut route = CompiledRoute::new(route_key);
    for (i, entry) in raw.policy.iter().enumerate() {
        route.policy.push(parse_step(entry, &format!("{}.policy[{}]", route_key, i))?);
    }
    for (i, entry) in raw.post_policy.iter().enumerate() {
        route.post_policy.push(parse_step(entry, &format!("{}.post_policy[{}]", route_key, i))?);
    }
    for (field, chain) in &raw.args {
        let pipeline = parse_pipeline(chain).map_err(|e| ParseError::Rule {
            rule: format!("args.{}: {:?}", field, chain),
            msg: format!("{}", e),
        })?;
        route.args.push(FieldRule {
            field: field.clone(),
            pipeline,
            source: format!("{}.args.{}", route_key, field),
        });
    }
    for (field, chain) in &raw.result {
        let pipeline = parse_pipeline(chain).map_err(|e| ParseError::Rule {
            rule: format!("result.{}: {:?}", field, chain),
            msg: format!("{}", e),
        })?;
        route.result.push(FieldRule {
            field: field.clone(),
            pipeline,
            source: format!("{}.result.{}", route_key, field),
        });
    }
    Ok(Some(route))
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attributes::AttributeBag;
    use crate::evaluator::{evaluate_rules, Decision};

    // ----- Lexer -----

    #[test]
    fn lex_basic() {
        let toks = Lexer::new("delegation.depth > 2").tokenize_all().unwrap();
        assert_eq!(toks, vec![
            Tok::Ident("delegation.depth".into()),
            Tok::Gt,
            Tok::IntLit(2),
        ]);
    }

    #[test]
    fn lex_strings_both_quotes() {
        let a = Lexer::new(r#""double""#).tokenize_all().unwrap();
        let b = Lexer::new(r#"'single'"#).tokenize_all().unwrap();
        assert_eq!(a, vec![Tok::StringLit("double".into())]);
        assert_eq!(b, vec![Tok::StringLit("single".into())]);
    }

    #[test]
    fn lex_keywords_vs_idents() {
        let toks = Lexer::new("require(role.hr) & authenticated").tokenize_all().unwrap();
        assert_eq!(toks, vec![
            Tok::Require, Tok::LParen,
            Tok::Ident("role.hr".into()),
            Tok::RParen, Tok::And,
            Tok::Ident("authenticated".into()),
        ]);
    }

    #[test]
    fn lex_rejects_single_equals() {
        let err = Lexer::new("a = 1").tokenize_all().unwrap_err();
        assert!(format!("{}", err).contains("expected `==`"));
    }

    // ----- Predicate parser -----

    #[test]
    fn pred_bare_identifier() {
        let e = parse_predicate("authenticated").unwrap();
        assert_eq!(e, Expression::Condition(Condition::IsTrue { key: "authenticated".into() }));
    }

    #[test]
    fn pred_comparison() {
        let e = parse_predicate("delegation.depth > 2").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::Comparison {
                key: "delegation.depth".into(),
                op: CompareOp::Gt,
                value: Literal::Int(2),
            })
        );
    }

    #[test]
    fn pred_contains() {
        let e = parse_predicate(r#"session.labels contains "PII""#).unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::Comparison {
                key: "session.labels".into(),
                op: CompareOp::Contains,
                value: Literal::String("PII".into()),
            })
        );
    }

    #[test]
    fn pred_precedence_or_lowest_and_middle_not_highest() {
        // `!a & b | c` should parse as `(!a & b) | c`.
        let e = parse_predicate("!a & b | c").unwrap();
        match e {
            Expression::Or(parts) => {
                assert_eq!(parts.len(), 2);
                match &parts[0] {
                    Expression::And(_) => {}
                    other => panic!("first OR branch should be AND, got {:?}", other),
                }
            }
            other => panic!("top-level should be OR, got {:?}", other),
        }
    }

    #[test]
    fn pred_parens_override_precedence() {
        // `(role.finance | role.admin) & !delegated` from DSL §2.5.
        let e = parse_predicate("(role.finance | role.admin) & !delegated").unwrap();
        match e {
            Expression::And(parts) => {
                assert_eq!(parts.len(), 2);
                matches!(parts[0], Expression::Or(_));
                matches!(parts[1], Expression::Not(_));
            }
            other => panic!("expected top-level AND, got {:?}", other),
        }
    }

    #[test]
    fn pred_require_rejected_as_predicate() {
        // require() is a rule-level shorthand per DSL §8, not a sub-predicate.
        // Trying to use it inside a predicate expression must fail clearly.
        let err = parse_predicate("require(authenticated)").unwrap_err();
        assert!(format!("{}", err).contains("rule-level shorthand"));
    }

    #[test]
    fn rule_require_single_arg_desugars_to_isfalse_and_deny() {
        // require(X)  →  Rule { condition: IsFalse(X), action: Deny }   (DSL §8.1)
        let r = parse_rule("require(authenticated)", "test").unwrap();
        assert!(matches!(r.action, Action::Deny { reason: None }));
        assert_eq!(
            r.condition,
            Expression::Condition(Condition::IsFalse { key: "authenticated".into() }),
        );
    }

    #[test]
    fn rule_require_comma_is_and_desugars_to_or_of_isfalse() {
        // require(X, Y)  →  Or([IsFalse(X), IsFalse(Y)]) + Deny   (DSL §8.1)
        // i.e., "deny if any are falsy" = "any are falsy → deny"
        let r = parse_rule("require(role.hr, perm.view_ssn)", "test").unwrap();
        assert_eq!(
            r.condition,
            Expression::Or(vec![
                Expression::Condition(Condition::IsFalse { key: "role.hr".into() }),
                Expression::Condition(Condition::IsFalse { key: "perm.view_ssn".into() }),
            ]),
        );
    }

    #[test]
    fn rule_require_pipe_is_or_desugars_to_and_of_isfalse() {
        // require(X | Y)  →  And([IsFalse(X), IsFalse(Y)]) + Deny   (DSL §8.1)
        // i.e., "deny only if all are falsy" = "all are falsy → deny"
        let r = parse_rule("require(role.finance | role.admin)", "test").unwrap();
        assert_eq!(
            r.condition,
            Expression::And(vec![
                Expression::Condition(Condition::IsFalse { key: "role.finance".into() }),
                Expression::Condition(Condition::IsFalse { key: "role.admin".into() }),
            ]),
        );
    }

    #[test]
    fn rule_require_mixed_rejected() {
        let err = parse_rule("require(a, b | c)", "test").unwrap_err();
        assert!(format!("{}", err).contains("cannot mix"));
    }

    #[test]
    fn pred_eq_with_ident_rhs_rejected_with_in_hint() {
        // `subject.type == allowed_types` — `==` doesn't take an ident RHS,
        // and the error should hint at `in` for set membership.
        let err = parse_predicate("subject.type == allowed_types").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("RHS-as-identifier"));
        assert!(msg.contains("set membership use"));
    }

    #[test]
    fn pred_in_set_basic() {
        let e = parse_predicate("subject.type in allowed_types").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::InSet {
                value_key: "subject.type".into(),
                set_key: "allowed_types".into(),
                negate: false,
            }),
        );
    }

    #[test]
    fn pred_not_in_set() {
        let e = parse_predicate("subject.type not in blocked_types").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::InSet {
                value_key: "subject.type".into(),
                set_key: "blocked_types".into(),
                negate: true,
            }),
        );
    }

    #[test]
    fn pred_exists_basic() {
        let e = parse_predicate("exists(args.amount)").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::Exists { key: "args.amount".into() }),
        );
    }

    #[test]
    fn pred_exists_inside_compound() {
        // exists() is a sub-predicate (unlike require) — can nest in & / |.
        let e = parse_predicate("exists(args.amount) & args.amount > 0").unwrap();
        match e {
            Expression::And(parts) => {
                assert_eq!(parts.len(), 2);
                assert_eq!(
                    parts[0],
                    Expression::Condition(Condition::Exists { key: "args.amount".into() }),
                );
            }
            other => panic!("expected And, got {:?}", other),
        }
    }

    #[test]
    fn pred_exists_requires_paren_and_ident() {
        assert!(parse_predicate("exists").is_err());
        assert!(parse_predicate("exists()").is_err());
        assert!(parse_predicate("exists(authenticated").is_err());
    }

    #[test]
    fn pred_trailing_tokens_rejected() {
        let err = parse_predicate("a b").unwrap_err();
        assert!(format!("{}", err).contains("trailing"));
    }

    // ----- Rule parser -----

    #[test]
    fn rule_predicate_action_form() {
        let r = parse_rule("delegation.depth > 2: deny", "test").unwrap();
        match r.action {
            Action::Deny { .. } => {}
            other => panic!("expected Deny, got {:?}", other),
        }
        match r.condition {
            Expression::Condition(Condition::Comparison { .. }) => {}
            other => panic!("expected Comparison, got {:?}", other),
        }
    }

    #[test]
    fn rule_predicate_only_defaults_to_deny() {
        // DSL §2: missing action defaults to deny.
        let r = parse_rule("!authenticated", "test").unwrap();
        assert!(matches!(r.action, Action::Deny { .. }));
    }

    #[test]
    fn rule_explicit_allow() {
        let r = parse_rule("role.admin: allow", "test").unwrap();
        assert!(matches!(r.action, Action::Allow));
    }

    #[test]
    fn rule_bare_action_unconditional() {
        // Bare `- deny` and `- allow` are unconditional rules with
        // Expression::Always as the predicate (DSL §3.1).
        let r = parse_rule("deny", "test").unwrap();
        assert_eq!(r.condition, Expression::Always);
        assert!(matches!(r.action, Action::Deny { reason: None }));

        let r = parse_rule("allow", "test").unwrap();
        assert_eq!(r.condition, Expression::Always);
        assert!(matches!(r.action, Action::Allow));
    }

    #[test]
    fn rule_step_kinds_rejected_clearly() {
        for s in ["plugin(rate_limiter)", "cedar:(action: read)", "opa(path)", "taint(audit)"] {
            let err = parse_rule(s, "test").unwrap_err();
            assert!(
                matches!(err, ParseError::UnsupportedStep { .. }),
                "expected UnsupportedStep for `{}`, got {:?}", s, err
            );
        }
    }

    #[test]
    fn rule_deny_with_reason_rejected() {
        // DSL has no `deny "reason"` form — reasons come from PDPs.
        let err = parse_rule(r#"authenticated: deny "go away""#, "test").unwrap_err();
        assert!(format!("{}", err).contains("only `deny` and `allow`"));
    }

    // ----- Colon-splitting edge cases -----

    #[test]
    fn split_respects_quotes_and_parens() {
        // The `:` inside parens / quotes shouldn't be the separator.
        let r = parse_rule(
            r#"session.labels contains "a:b": deny"#,
            "test",
        ).unwrap();
        assert!(matches!(r.action, Action::Deny { .. }));
        if let Expression::Condition(Condition::Comparison { value, .. }) = r.condition {
            assert_eq!(value, Literal::String("a:b".into()));
        } else {
            panic!("expected Comparison");
        }
    }

    // ----- YAML compilation -----

    #[test]
    fn compile_simple_route() {
        let yaml = r#"
routes:
  get_compensation:
    policy:
      - "require(authenticated)"
      - "require(role.hr | role.finance)"
      - "delegation.depth > 2 & include_ssn: deny"
"#;
        let routes = compile_config(yaml).unwrap();
        let route = routes.get("get_compensation").expect("route missing");
        assert_eq!(route.policy.len(), 3);
        assert!(route.declared_phases().contains(crate::rules::Phase::Policy));
    }

    #[test]
    fn compile_omits_routes_without_apl_blocks() {
        let yaml = r#"
routes:
  legacy:
    plugins: [rate_limiter, audit_logger]
  apl_route:
    policy:
      - "require(authenticated)"
"#;
        let routes = compile_config(yaml).unwrap();
        assert!(routes.contains_key("apl_route"));
        assert!(!routes.contains_key("legacy"), "legacy route should be omitted, not compiled");
    }

    #[test]
    fn compile_unknown_top_level_keys_ignored() {
        let yaml = r#"
version: "0.1"
policy_evaluator:
  kind: apl
plugins:
  - name: rate_limiter
imports:
  - "./shared.yaml"
routes:
  ping:
    policy:
      - "require(authenticated)"
"#;
        let routes = compile_config(yaml).unwrap();
        assert!(routes.contains_key("ping"));
    }

    #[test]
    fn compile_propagates_rule_errors_with_source() {
        let yaml = r#"
routes:
  bad:
    policy:
      - "subject.id == garbage_ident"
"#;
        let err = compile_config(yaml).unwrap_err();
        // RHS-as-identifier is rejected; the error mentions the offending input.
        let msg = format!("{}", err);
        assert!(
            msg.contains("RHS-as-identifier") || msg.contains("garbage_ident"),
            "error message should reference the failure: {}", msg,
        );
    }

    #[test]
    fn compile_plugin_step_string_form() {
        let yaml = r#"
routes:
  rate_limited:
    policy:
      - "plugin(rate_limiter)"
"#;
        let routes = compile_config(yaml).unwrap();
        let route = routes.get("rate_limited").unwrap();
        assert_eq!(route.policy.len(), 1);
        match &route.policy[0] {
            Step::Plugin { name } => assert_eq!(name, "rate_limiter"),
            other => panic!("expected Step::Plugin, got {:?}", other),
        }
    }

    #[test]
    fn compile_taint_step_string_form() {
        let yaml = r#"
routes:
  audit_marked:
    policy:
      - "taint(audit, session)"
"#;
        let routes = compile_config(yaml).unwrap();
        let route = routes.get("audit_marked").unwrap();
        match &route.policy[0] {
            Step::Taint { label, scopes } => {
                assert_eq!(label, "audit");
                assert_eq!(scopes, &vec![TaintScope::Session]);
            }
            other => panic!("expected Step::Taint, got {:?}", other),
        }
    }

    #[test]
    fn compile_pdp_call_cedar_map_form() {
        // Cedar uses the `cedar:` key with args inline + on_deny/on_allow.
        let yaml = r#"
routes:
  authz_check:
    policy:
      - cedar:
          action: read
          resource: employee
          on_deny:
            - deny
          on_allow:
            - "plugin(audit_logger)"
"#;
        let routes = compile_config(yaml).unwrap();
        let route = routes.get("authz_check").unwrap();
        match &route.policy[0] {
            Step::Pdp { call, on_deny, on_allow } => {
                assert_eq!(call.dialect, PdpDialect::Cedar);
                // Cedar args are a map: action + resource (with reaction
                // keys stripped out).
                let args_map = call.args.as_mapping().expect("cedar args should be a map");
                assert!(args_map.contains_key(serde_yaml::Value::String("action".into())));
                assert!(args_map.contains_key(serde_yaml::Value::String("resource".into())));
                assert!(!args_map.contains_key(serde_yaml::Value::String("on_deny".into())));
                assert_eq!(on_deny.len(), 1);
                assert_eq!(on_allow.len(), 1);
            }
            other => panic!("expected Step::Pdp, got {:?}", other),
        }
    }

    #[test]
    fn compile_pdp_call_opa_paren_form() {
        // OPA uses `opa("path"):` with the path inside parens + body is reactions.
        let yaml = r#"
routes:
  opa_check:
    policy:
      - 'opa("hr/compensation/deny"):':
          on_deny:
            - deny
"#;
        let routes = compile_config(yaml).unwrap();
        let route = routes.get("opa_check").unwrap();
        match &route.policy[0] {
            Step::Pdp { call, on_deny, .. } => {
                assert_eq!(call.dialect, PdpDialect::Opa);
                // OPA args are a string (the path).
                assert!(call.args.as_str().unwrap().contains("hr/compensation/deny"));
                assert_eq!(on_deny.len(), 1);
            }
            other => panic!("expected Step::Pdp, got {:?}", other),
        }
    }

    #[test]
    fn compile_pdp_unknown_dialect_becomes_custom() {
        let yaml = r#"
routes:
  custom_pdp:
    policy:
      - my_engine:
          on_deny: [deny]
"#;
        let routes = compile_config(yaml).unwrap();
        match &routes.get("custom_pdp").unwrap().policy[0] {
            Step::Pdp { call, .. } => {
                assert_eq!(call.dialect, PdpDialect::Custom("my_engine".into()));
            }
            other => panic!("expected Pdp, got {:?}", other),
        }
    }

    // ----- End-to-end with evaluator -----

    #[tokio::test]
    async fn end_to_end_hr_compensation() {
        let yaml = r#"
routes:
  get_compensation:
    policy:
      - "require(authenticated)"
      - "require(role.hr | role.finance)"
      - "delegation.depth > 2: deny"
"#;
        let routes = compile_config(yaml).unwrap();
        let route = routes.get("get_compensation").unwrap();

        let pdp = NullPdpResolver;
        let plugins = NullPluginInvoker;

        // Alice: authenticated, hr role, depth=1 → allow.
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        bag.set("role.hr", true);
        bag.set("delegation.depth", 1_i64);
        assert_eq!(
            crate::evaluate_steps(&route.policy, &bag, &pdp, &plugins).await,
            Decision::Allow,
        );

        // Same Alice but depth=3 → deny (third rule fires).
        bag.set("delegation.depth", 3_i64);
        match crate::evaluate_steps(&route.policy, &bag, &pdp, &plugins).await {
            Decision::Deny { rule_source, .. } => {
                assert!(rule_source.contains("policy[2]"), "expected policy[2], got {}", rule_source);
            }
            d => panic!("expected Deny, got {:?}", d),
        }

        // Bob: authenticated but neither hr nor finance → deny on rule 1.
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        bag.set("delegation.depth", 1_i64);
        match crate::evaluate_steps(&route.policy, &bag, &pdp, &plugins).await {
            Decision::Deny { rule_source, .. } => {
                assert!(rule_source.contains("policy[1]"), "expected policy[1], got {}", rule_source);
            }
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    // Test fixtures for async evaluator — null resolvers that nothing in
    // a pure-rule route should ever invoke.
    struct NullPdpResolver;
    #[async_trait::async_trait]
    impl crate::PdpResolver for NullPdpResolver {
        fn dialect(&self) -> crate::PdpDialect { crate::PdpDialect::Cedar }
        async fn evaluate(
            &self,
            _call: &crate::PdpCall,
            _bag: &crate::AttributeBag,
        ) -> Result<crate::PdpDecision, crate::PdpError> {
            panic!("NullPdpResolver should not be invoked in pure-rule tests");
        }
    }

    struct NullPluginInvoker;
    #[async_trait::async_trait]
    impl crate::PluginInvoker for NullPluginInvoker {
        async fn invoke(
            &self,
            _name: &str,
            _bag: &crate::AttributeBag,
            _invocation: crate::PluginInvocation<'_>,
        ) -> Result<crate::PluginOutcome, crate::PluginError> {
            panic!("NullPluginInvoker should not be invoked in pure-rule tests");
        }
    }

    // ----- Pipeline parsing -----

    #[test]
    fn pipeline_simple_bare_stages() {
        let p = parse_pipeline("str").unwrap();
        assert_eq!(p.stages, vec![Stage::Type(TypeCheck::Str)]);

        let p = parse_pipeline("omit").unwrap();
        assert_eq!(p.stages, vec![Stage::Omit]);

        let p = parse_pipeline("hash").unwrap();
        assert_eq!(p.stages, vec![Stage::Hash]);
    }

    #[test]
    fn pipeline_chains_split_on_pipe() {
        let p = parse_pipeline("str | mask(4)").unwrap();
        assert_eq!(p.stages, vec![
            Stage::Type(TypeCheck::Str),
            Stage::Mask { keep_last: 4 },
        ]);

        let p = parse_pipeline("int | 0..1M").unwrap();
        assert_eq!(p.stages, vec![
            Stage::Type(TypeCheck::Int),
            Stage::Range { min: Some(0), max: Some(1_000_000) },
        ]);
    }

    #[test]
    fn pipeline_pipe_inside_parens_does_not_split() {
        // `redact(!a | b)` is one stage; the inner `|` is OR inside a
        // predicate condition, not a chain separator.
        let p = parse_pipeline("str | redact(!perm.view_ssn | role.admin)").unwrap();
        assert_eq!(p.stages.len(), 2);
        match &p.stages[1] {
            Stage::Redact { condition: Some(_) } => {}
            other => panic!("expected Redact with condition, got {:?}", other),
        }
    }

    #[test]
    fn pipeline_length_constraints() {
        let p = parse_pipeline("len(..500)").unwrap();
        assert_eq!(p.stages, vec![Stage::Length { min: None, max: Some(500) }]);
        let p = parse_pipeline("len(10..50)").unwrap();
        assert_eq!(p.stages, vec![Stage::Length { min: Some(10), max: Some(50) }]);
        let p = parse_pipeline("len(8..)").unwrap();
        assert_eq!(p.stages, vec![Stage::Length { min: Some(8), max: None }]);
    }

    #[test]
    fn pipeline_range_with_suffixes() {
        let p = parse_pipeline("0..10k").unwrap();
        assert_eq!(p.stages, vec![Stage::Range { min: Some(0), max: Some(10_000) }]);
        let p = parse_pipeline("0..1M").unwrap();
        assert_eq!(p.stages, vec![Stage::Range { min: Some(0), max: Some(1_000_000) }]);
        let p = parse_pipeline("..500").unwrap();
        assert_eq!(p.stages, vec![Stage::Range { min: None, max: Some(500) }]);
    }

    #[test]
    fn pipeline_enum_unquoted_and_quoted() {
        let p = parse_pipeline("enum(low, medium, high)").unwrap();
        assert_eq!(p.stages, vec![Stage::Enum {
            values: vec!["low".into(), "medium".into(), "high".into()],
        }]);
        let p = parse_pipeline(r#"enum("a", "b")"#).unwrap();
        assert_eq!(p.stages, vec![Stage::Enum {
            values: vec!["a".into(), "b".into()],
        }]);
    }

    #[test]
    fn pipeline_redact_with_predicate_condition() {
        let p = parse_pipeline("str | redact(!perm.view_ssn)").unwrap();
        assert_eq!(p.stages.len(), 2);
        match &p.stages[1] {
            Stage::Redact { condition: Some(Expression::Not(inner)) } => {
                match inner.as_ref() {
                    Expression::Condition(Condition::IsTrue { key }) => {
                        assert_eq!(key, "perm.view_ssn");
                    }
                    other => panic!("expected IsTrue(perm.view_ssn), got {:?}", other),
                }
            }
            other => panic!("expected Redact with Not condition, got {:?}", other),
        }
    }

    #[test]
    fn pipeline_taint_scopes() {
        let p = parse_pipeline("taint(PII)").unwrap();
        assert_eq!(p.stages, vec![Stage::Taint {
            label: "PII".into(),
            scopes: vec![TaintScope::Session],
        }]);
        let p = parse_pipeline("taint(PII, message)").unwrap();
        assert_eq!(p.stages, vec![Stage::Taint {
            label: "PII".into(),
            scopes: vec![TaintScope::Message],
        }]);
        let p = parse_pipeline("taint(PII, [session, message])").unwrap();
        assert_eq!(p.stages, vec![Stage::Taint {
            label: "PII".into(),
            scopes: vec![TaintScope::Session, TaintScope::Message],
        }]);
    }

    #[test]
    fn pipeline_unknown_stage_rejected() {
        let err = parse_pipeline("nonsense").unwrap_err();
        assert!(format!("{}", err).contains("unknown stage"));
    }

    #[test]
    fn pipeline_omit_with_args_rejected() {
        // omit has no conditional form per DSL §4.1.
        let err = parse_pipeline("omit(!perm.x)").unwrap_err();
        assert!(format!("{}", err).contains("omit takes no arguments"));
    }

    // ----- YAML compilation with pipelines -----

    #[test]
    fn compile_route_with_args_and_result() {
        let yaml = r#"
routes:
  get_compensation:
    args:
      employee_id: "uuid"
      amount: "int | 0..1M"
    result:
      ssn: "str | redact(!perm.view_ssn)"
      employee_id: "str | mask(4)"
      internal_notes: "omit"
"#;
        let routes = compile_config(yaml).unwrap();
        let route = routes.get("get_compensation").expect("missing route");
        assert_eq!(route.args.len(), 2);
        assert_eq!(route.result.len(), 3);

        // Pull out the ssn pipeline and confirm shape.
        let ssn = route.result.iter().find(|f| f.field == "ssn").unwrap();
        assert_eq!(ssn.pipeline.stages.len(), 2);
        assert!(matches!(ssn.pipeline.stages[0], Stage::Type(TypeCheck::Str)));
        assert!(matches!(ssn.pipeline.stages[1], Stage::Redact { condition: Some(_) }));

        // declared_phases should include Result and Args now.
        let phases = route.declared_phases();
        assert!(phases.contains(crate::rules::Phase::Args));
        assert!(phases.contains(crate::rules::Phase::Result));
    }

    #[test]
    fn compile_route_with_only_args_still_compiles() {
        // A route with no `policy:` but with `args:` validators is still
        // an APL route (declared_phases is non-empty).
        let yaml = r#"
routes:
  validate_only:
    args:
      employee_id: "uuid"
"#;
        let routes = compile_config(yaml).unwrap();
        assert!(routes.contains_key("validate_only"));
    }

    #[test]
    fn compile_propagates_pipeline_parse_errors() {
        let yaml = r#"
routes:
  bad:
    result:
      x: "nonsense"
"#;
        let err = compile_config(yaml).unwrap_err();
        assert!(format!("{}", err).contains("unknown stage"));
    }
}
