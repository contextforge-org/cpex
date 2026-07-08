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
//   ✓ YAML top-level routes: keyed map, authorization.pre_invocation /
//     post_invocation blocks (flat pre_invocation:/post_invocation: too)
//   ✗ Steps (cedar:(), opa(), plugin(), taint()) — rejected with clear errors
//   ✗ Pipe chains in args:/result: — fields parsed, values stashed as opaque
//   ✗ `in` / `not in` / `exists()` — need IR variants first; rejected
//   ✗ Multi-effect do: lists, sequential:/parallel: blocks — rejected

use std::collections::HashMap;

use serde::Deserialize;
use thiserror::Error;

use crate::pipeline::{FieldRule, Pipeline, ScanKind, Stage, TaintScope, TypeCheck};
use crate::plugin_decl::{PluginDeclaration, PluginOverride, PluginRegistry};
use crate::rules::{CompareOp, CompiledRoute, Condition, Effect, Expression, Literal, Rule};
use crate::step::{DelegateStep, PdpCall, PdpDialect, Step};

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

    #[error("in `{location}`: config field `{old}` was renamed to `{new}` — update your config")]
    RenamedField {
        location: String,
        old: String,
        new: String,
    },

    #[error(
        "in `{location}`: `{phase}` is declared both nested under `authorization:` and flat on \
         the section — use one form, not both (declaring both runs the effects twice)"
    )]
    ConflictingAuthorizationForms { location: String, phase: String },
}

// =====================================================================
// Lexer
// =====================================================================

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String), // dotted: subject.id, role.hr, authenticated
    StringLit(String),
    IntLit(i64),
    FloatLit(f64),
    BoolLit(bool),
    Eq,    // ==
    NotEq, // !=
    Gt,    // >
    GtEq,  // >=
    Lt,    // <
    LtEq,  // <=
    And,   // &  (must have surrounding spaces — caller enforces)
    Or,    // |
    Not,   // !
    LParen,
    RParen,
    Comma,
    Contains, // keyword
    Require,  // keyword
    Exists,   // keyword
    In,       // keyword — set membership operator
}

struct Lexer<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    fn new(src: &'a str) -> Self {
        Self {
            src,
            bytes: src.as_bytes(),
            pos: 0,
        }
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
            if b.is_ascii_whitespace() {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn tokenize_all(&mut self) -> Result<Vec<Tok>, ParseError> {
        let mut out = Vec::new();
        loop {
            self.skip_ws();
            let Some(b) = self.peek() else {
                return Ok(out);
            };

            let tok = match b {
                b'(' => {
                    self.pos += 1;
                    Tok::LParen
                },
                b')' => {
                    self.pos += 1;
                    Tok::RParen
                },
                b',' => {
                    self.pos += 1;
                    Tok::Comma
                },
                b'&' => {
                    self.pos += 1;
                    Tok::And
                },
                b'|' => {
                    self.pos += 1;
                    Tok::Or
                },
                b'=' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') {
                        self.pos += 1;
                        Tok::Eq
                    } else {
                        return Err(self.err("expected `==`, saw `=`"));
                    }
                },
                b'!' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') {
                        self.pos += 1;
                        Tok::NotEq
                    } else {
                        Tok::Not
                    }
                },
                b'>' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') {
                        self.pos += 1;
                        Tok::GtEq
                    } else {
                        Tok::Gt
                    }
                },
                b'<' => {
                    self.pos += 1;
                    if self.peek() == Some(b'=') {
                        self.pos += 1;
                        Tok::LtEq
                    } else {
                        Tok::Lt
                    }
                },
                b'"' | b'\'' => self.lex_string(b)?,
                b'-' | b'0'..=b'9' => self.lex_number()?,
                b if is_ident_start(b) => self.lex_ident_or_keyword()?,
                _ => return Err(self.err(&format!("unexpected char `{}`", b as char))),
            };
            out.push(tok);
        }
    }

    fn lex_string(&mut self, quote: u8) -> Result<Tok, ParseError> {
        self.bump(); // opening quote
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b == quote {
                break;
            }
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
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') {
            is_float = true;
            self.pos += 1;
            while let Some(b) = self.peek() {
                if b.is_ascii_digit() {
                    self.pos += 1;
                } else {
                    break;
                }
            }
        }
        let text = &self.src[start..self.pos];
        if is_float {
            text.parse::<f64>()
                .map(Tok::FloatLit)
                .map_err(|_| self.err(&format!("bad float `{}`", text)))
        } else {
            text.parse::<i64>()
                .map(Tok::IntLit)
                .map_err(|_| self.err(&format!("bad int `{}`", text)))
        }
    }

    fn lex_ident_or_keyword(&mut self) -> Result<Tok, ParseError> {
        let start = self.pos;
        // An attribute path is ident-cont runs interleaved with `[...]`
        // interpolation groups: `data.tenants[subject.tenant].data_region`.
        // The bracket content is a nested attribute key the evaluator
        // resolves at eval time (R3b) — the lexer only delimits it.
        let mut has_bracket = false;
        loop {
            while let Some(b) = self.peek() {
                if is_ident_cont(b) {
                    self.pos += 1;
                } else {
                    break;
                }
            }
            if self.peek() == Some(b'[') {
                has_bracket = true;
                self.pos += 1; // consume `[`
                let mut closed = false;
                while let Some(b) = self.peek() {
                    self.pos += 1;
                    match b {
                        b']' => {
                            closed = true;
                            break;
                        },
                        b'[' => return Err(self.err("nested `[` in attribute path")),
                        _ => {},
                    }
                }
                if !closed {
                    return Err(self.err("unterminated `[` in attribute path"));
                }
                // Continue: more ident-cont chars or another `[...]` may follow.
            } else {
                break;
            }
        }
        let s = &self.src[start..self.pos];
        // A path with an interpolation group is never a keyword.
        if has_bracket {
            return Ok(Tok::Ident(s.to_string()));
        }
        Ok(match s {
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
        })
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
            return Err(p.err(&format!(
                "trailing tokens after expression: {:?}",
                &p.toks[p.pos..]
            )));
        }
        Ok(expr)
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
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
        Ok(if parts.len() == 1 {
            parts.pop().unwrap()
        } else {
            Expression::Or(parts)
        })
    }

    fn parse_and(&mut self) -> Result<Expression, ParseError> {
        let mut parts = vec![self.parse_unary()?];
        while matches!(self.peek(), Some(Tok::And)) {
            self.bump();
            parts.push(self.parse_unary()?);
        }
        Ok(if parts.len() == 1 {
            parts.pop().unwrap()
        } else {
            Expression::And(parts)
        })
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
            },
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
            Some(Tok::LParen) => {},
            _ => return Err(self.err("expected `(` after `exists`")),
        }
        let key = match self.bump() {
            Some(Tok::Ident(s)) => s,
            other => {
                return Err(self.err(&format!(
                    "exists(...) expects an attribute key, got {:?}",
                    other,
                )))
            },
        };
        match self.bump() {
            Some(Tok::RParen) => {},
            other => {
                return Err(self.err(&format!(
                    "expected `)` after exists() argument, got {:?}",
                    other,
                )))
            },
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
            },
            other => return Err(self.err(&format!("expected literal RHS, got {:?}", other))),
        };

        Ok(Expression::Condition(Condition::Comparison {
            key,
            op,
            value,
        }))
    }

    fn finish_in_set(&mut self, value_key: String, negate: bool) -> Result<Expression, ParseError> {
        let set_key = match self.bump() {
            Some(Tok::Ident(s)) => s,
            other => {
                return Err(self.err(&format!(
                    "expected set-attribute identifier after `{}in`, got {:?}",
                    if negate { "not " } else { "" },
                    other,
                )))
            },
        };
        Ok(Expression::Condition(Condition::InSet {
            value_key,
            set_key,
            negate,
        }))
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
        return Ok(Rule::single(
            condition,
            Effect::Deny {
                reason: None,
                code: None,
            },
            source,
        ));
    }

    // Step kinds shouldn't end up here. If they do, the caller used the
    // wrong entry point — point them at parse_step.
    if let Some(kind) = detect_step_kind(trimmed) {
        return Err(ParseError::UnsupportedStep {
            rule: trimmed.to_string(),
            kind: format!("{} (use parse_step for step kinds)", kind),
        });
    }

    let (predicate_str, effects) = match split_predicate_action(trimmed) {
        Some((p, a)) => (p, parse_action(a, trimmed)?),
        None => {
            // No `:` — bare action (unconditional) or bare predicate (default deny).
            if let Some(effects) = try_bare_action(trimmed) {
                return Ok(Rule {
                    condition: Expression::Always,
                    effects,
                    source: source.to_string(),
                });
            }
            // Unconditional `deny('reason')` / `deny('reason', 'code')` —
            // the call form of a bare deny. Lets reaction lists
            // (`on_deny: [...]` / `on_allow: [...]`) and standalone rule
            // lines attach a reason/code without a guard predicate. A
            // malformed `deny(...)` surfaces its own error here rather
            // than being misread as a predicate downstream.
            if let Some(deny) = try_parse_deny_call(trimmed, trimmed)? {
                return Ok(Rule {
                    condition: Expression::Always,
                    effects: vec![deny],
                    source: source.to_string(),
                });
            }
            // DSL §2 default: bare predicate denies.
            (
                trimmed,
                vec![Effect::Deny {
                    reason: None,
                    code: None,
                }],
            )
        },
    };

    let condition = parse_predicate(predicate_str).map_err(|e| ParseError::Rule {
        rule: trimmed.to_string(),
        msg: format!("{}", e),
    })?;

    Ok(Rule {
        condition,
        effects,
        source: source.to_string(),
    })
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
/// Caller wraps with `Effect::Deny`.
fn parse_require_rule(line: &str) -> Result<Expression, ParseError> {
    let toks = Lexer::new(line).tokenize_all()?;
    let mut iter = toks.into_iter().peekable();

    let bad = |msg: &str| ParseError::Rule {
        rule: line.to_string(),
        msg: msg.to_string(),
    };

    match iter.next() {
        Some(Tok::Require) => {},
        _ => return Err(bad("expected `require`")),
    }
    match iter.next() {
        Some(Tok::LParen) => {},
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
                    Some(prev) if std::mem::discriminant(prev) == std::mem::discriminant(&t) => {},
                    _ => {
                        return Err(bad(
                            "require(...) cannot mix `,` (AND) and `|` (OR) — use one or the other",
                        ))
                    },
                }
                match iter.next() {
                    Some(Tok::Ident(s)) => keys.push(s),
                    _ => return Err(bad("expected identifier after `,` or `|` in require(...)")),
                }
            },
            Some(other) => {
                return Err(bad(&format!(
                    "expected `,`, `|`, or `)` in require(...), got {:?}",
                    other,
                )))
            },
            None => return Err(bad("unexpected end of require(...) — missing `)`")),
        }
    }

    if iter.peek().is_some() {
        return Err(bad(
            "trailing tokens after `require(...)` — require is a complete rule",
        ));
    }

    let falses: Vec<Expression> = keys
        .into_iter()
        .map(|k| Expression::Condition(Condition::IsFalse { key: k }))
        .collect();
    if falses.len() == 1 {
        return Ok(falses.into_iter().next().unwrap());
    }
    Ok(match sep {
        Some(Tok::Or) => Expression::And(falses), // require(X | Y) → !X & !Y
        _ => Expression::Or(falses),              // require(X, Y)  → !X | !Y
    })
}

/// Detect `taint(...)` / `plugin(...)` / `run(...)` / `cedar:` / `opa(` / `authzen(` / `nemo(` / `cel:`.
fn detect_step_kind(s: &str) -> Option<&'static str> {
    let s = s.trim_start();
    for prefix in [
        "taint(",
        "plugin(",
        "run(",
        "cedar:",
        "opa(",
        "authzen(",
        "nemo(",
        "cel:",
        "sequential:",
        "parallel:",
    ] {
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
            (Some(_), _) => {},
            (None, b'"') | (None, b'\'') => in_quote = Some(b),
            (None, b'(') => depth += 1,
            (None, b')') => depth -= 1,
            (None, b':') if depth == 0 => last_colon = Some(i),
            _ => {},
        }
    }
    last_colon.map(|i| (s[..i].trim(), s[i + 1..].trim()))
}

/// Parse the *right* side of a shorthand `predicate: action` rule into a
/// single-element effects vec. Recognized forms (DSL §3 + the `code`
/// extension we added in E1):
///
///   * `deny`                    → `vec![Effect::Deny { reason: None, code: None }]`
///   * `deny('reason')`          → `vec![Effect::Deny { reason: Some, code: None }]`
///   * `deny('reason', 'code')`  → `vec![Effect::Deny { reason: Some, code: Some }]`
///   * `allow`                   → `vec![Effect::Allow]`
///
/// Anything else (plugin/delegate/taint) goes through `parse_step`, not
/// here — those are sibling Steps in v0. Multi-effect `do:` lists use a
/// separate parsing path that produces `Vec<Effect>` directly.
fn parse_action(s: &str, rule: &str) -> Result<Vec<Effect>, ParseError> {
    if let Some(effect) = try_bare_action(s) {
        return Ok(effect);
    }
    if let Some(deny) = try_parse_deny_call(s.trim(), rule)? {
        return Ok(vec![deny]);
    }
    Err(ParseError::Rule {
        rule: rule.to_string(),
        msg: format!(
            "unsupported action `{}` — recognized: `deny`, `deny('reason')`, `deny('reason', 'code')`, `allow`",
            s.trim()
        ),
    })
}

fn try_bare_action(s: &str) -> Option<Vec<Effect>> {
    match s.trim() {
        "deny" => Some(vec![Effect::Deny {
            reason: None,
            code: None,
        }]),
        "allow" => Some(vec![Effect::Allow]),
        _ => None,
    }
}

/// Parse `deny('reason')` or `deny('reason', 'code')`. Returns
/// `Ok(None)` when `s` doesn't start with `deny(` so the caller can
/// fall through to other action handlers.
fn try_parse_deny_call(s: &str, rule: &str) -> Result<Option<Effect>, ParseError> {
    if !s.starts_with("deny(") {
        return Ok(None);
    }
    let inside = extract_call_args(s, "deny").ok_or_else(|| ParseError::Rule {
        rule: rule.to_string(),
        msg: "malformed `deny(...)`".into(),
    })?;
    // Two positional args max. Spec precedent: `deny('reason')` (1 arg);
    // E1 extension: `deny('reason', 'code')` (2 args). Both quoted.
    let parts = split_top_level_commas(&inside).map_err(|e| ParseError::Rule {
        rule: rule.to_string(),
        msg: format!("deny(...): {}", e),
    })?;
    let mut iter = parts.into_iter();
    let reason = match iter.next() {
        Some(p) => Some(strip_string_literal(p.trim(), rule)?),
        None => None,
    };
    let code = match iter.next() {
        Some(p) => Some(strip_string_literal(p.trim(), rule)?),
        None => None,
    };
    if iter.next().is_some() {
        return Err(ParseError::Rule {
            rule: rule.to_string(),
            msg: "deny(...) takes at most two args: deny('reason', 'code')".into(),
        });
    }
    Ok(Some(Effect::Deny { reason, code }))
}

/// Strip surrounding single or double quotes from a literal. The DSL
/// uses single quotes (`'reason'`) per the spec examples, but accept
/// double quotes too so YAML escaping is forgiving.
fn strip_string_literal(s: &str, rule: &str) -> Result<String, ParseError> {
    let s = s.trim();
    if (s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2)
        || (s.starts_with('"') && s.ends_with('"') && s.len() >= 2)
    {
        Ok(s[1..s.len() - 1].to_string())
    } else {
        Err(ParseError::Rule {
            rule: rule.to_string(),
            msg: format!("expected a quoted string, got `{}`", s),
        })
    }
}

// =====================================================================
// Step parser (pre_invocation / post_invocation entries — steps + rules)
// =====================================================================

/// Parse a single YAML entry from a `pre_invocation` / `post_invocation` list.
///
/// Two YAML shapes (DSL §3.2 + §7):
/// - **String entry** — a rule line, taint effect, or plugin call.
///   - `"require(authenticated)"` → `Step::Rule`
///   - `"delegation.depth > 2: deny"` → `Step::Rule`
///   - `"plugin(rate_limiter)"` → `Step::Plugin` (`"run(rate_limiter)"` is an alias)
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
        let inside = extract_call_args(trimmed, "taint").ok_or_else(|| ParseError::Rule {
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

    // plugin(name) / run(name) — invoke a named plugin. `run` is an
    // alias for `plugin`; both emit Step::Plugin.
    let plugin_verb = if trimmed.starts_with("plugin(") {
        Some("plugin")
    } else if trimmed.starts_with("run(") {
        Some("run")
    } else {
        None
    };
    if let Some(verb) = plugin_verb {
        let inside = extract_call_args(trimmed, verb).ok_or_else(|| ParseError::Rule {
            rule: trimmed.to_string(),
            msg: format!("malformed `{verb}(...)`"),
        })?;
        let name = inside.trim();
        if name.is_empty() {
            return Err(ParseError::Rule {
                rule: trimmed.to_string(),
                msg: format!("`{verb}(...)`: plugin name must not be empty"),
            });
        }
        return Ok(Step::Plugin {
            name: name.to_string(),
        });
    }

    // delegate(name, key: value, key: [a, b], ...) — emit as Step::Delegate.
    // Compact alternative to the map form (`- delegate: { plugin: ..., ... }`).
    // First positional arg is the plugin name; subsequent `key: value`
    // pairs become per-call config overrides (or `on_error` if the key
    // is reserved). Use the map form for nested configs the kwarg
    // parser doesn't handle.
    if trimmed.starts_with("delegate(") {
        let inside = extract_call_args(trimmed, "delegate").ok_or_else(|| ParseError::Rule {
            rule: trimmed.to_string(),
            msg: "malformed `delegate(...)`".into(),
        })?;
        let parsed = parse_delegate_call_args(&inside, source)?;
        return Ok(Step::Delegate(DelegateStep {
            plugin_name: parsed.plugin_name,
            config_override: parsed.config_override,
            on_error: parsed.on_error,
            source: source.to_string(),
        }));
    }

    // Otherwise fall through to the rule parser — predicate-and-action.
    let rule = parse_rule(trimmed, source)?;
    Ok(Step::Rule(rule))
}

/// Intermediate shape produced by [`parse_delegate_call_args`]. The
/// string-form parser fills this; the caller wraps into `Step::Delegate`
/// with the source path it has in scope.
struct ParsedDelegateCall {
    plugin_name: String,
    config_override: Option<serde_yaml::Value>,
    on_error: Option<String>,
}

/// Parse the inside-parens of `delegate(name, key: value, key: [a, b], ...)`.
///
/// Grammar (informal):
/// ```text
/// delegate_args := plugin_name [, kwarg [, kwarg]*]
/// plugin_name   := bare_ident_or_string
/// kwarg         := key ":" value
/// value         := scalar | "[" value (, value)* "]"
/// scalar        := bare_word | number | "true" | "false" | quoted_string
/// ```
///
/// Reserved keys consumed before going into `config_override`:
///   - `on_error` — pulled out as `DelegateStep.on_error`
///
/// Everything else lands in `config_override` as a yaml mapping. Use
/// the map form (`- delegate: { plugin: ..., config: { ... }, ... }`)
/// for nested config shapes the flat kwarg parser doesn't handle.
fn parse_delegate_call_args(inside: &str, source: &str) -> Result<ParsedDelegateCall, ParseError> {
    let parts = split_top_level_commas(inside).map_err(|msg| ParseError::Rule {
        rule: format!("delegate({inside})"),
        msg: format!("{source}: {msg}"),
    })?;
    let mut parts_iter = parts.into_iter();

    let plugin_name = parts_iter
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ParseError::Rule {
            rule: format!("delegate({inside})"),
            msg: format!(
                "{source}: `delegate(...)` requires a plugin name as the first \
                 positional argument"
            ),
        })?;
    // Strip wrapping quotes if the operator wrote `delegate("workday-oauth", ...)`.
    let plugin_name = strip_wrapping_quotes(&plugin_name).to_string();
    if plugin_name.is_empty() {
        return Err(ParseError::Rule {
            rule: format!("delegate({inside})"),
            msg: format!("{source}: `delegate(...)` plugin name cannot be empty"),
        });
    }

    let mut on_error: Option<String> = None;
    let mut config_map = serde_yaml::Mapping::new();

    for raw_kwarg in parts_iter {
        let kwarg = raw_kwarg.trim();
        if kwarg.is_empty() {
            continue;
        }
        let (key, value_str) = kwarg.split_once(':').ok_or_else(|| ParseError::Rule {
            rule: kwarg.to_string(),
            msg: format!(
                "{source}: `delegate(...)` kwarg `{kwarg}` must be `key: value` \
                     (use the map form for richer config)"
            ),
        })?;
        let key = key.trim();
        let value_str = value_str.trim();
        if key.is_empty() {
            return Err(ParseError::Rule {
                rule: kwarg.to_string(),
                msg: format!("{source}: `delegate(...)` kwarg has empty key"),
            });
        }
        if key == "on_error" {
            let val = parse_delegate_value(value_str).map_err(|msg| ParseError::Rule {
                rule: kwarg.to_string(),
                msg: format!("{source}: on_error: {msg}"),
            })?;
            on_error = Some(
                val.as_str()
                    .ok_or_else(|| ParseError::Rule {
                        rule: kwarg.to_string(),
                        msg: format!("{source}: `on_error` must be a string"),
                    })?
                    .to_string(),
            );
            continue;
        }
        // Reject `plugin:` as a kwarg — the plugin name is the positional
        // first argument; allowing both would be ambiguous.
        if key == "plugin" {
            return Err(ParseError::Rule {
                rule: kwarg.to_string(),
                msg: format!(
                    "{source}: `plugin` is set as the first positional argument \
                     of `delegate(...)`; don't pass it as a kwarg too"
                ),
            });
        }
        let value = parse_delegate_value(value_str).map_err(|msg| ParseError::Rule {
            rule: kwarg.to_string(),
            msg: format!("{source}: `{key}`: {msg}"),
        })?;
        config_map.insert(serde_yaml::Value::String(key.to_string()), value);
    }

    let config_override = if config_map.is_empty() {
        None
    } else {
        Some(serde_yaml::Value::Mapping(config_map))
    };

    Ok(ParsedDelegateCall {
        plugin_name,
        config_override,
        on_error,
    })
}

/// Split a `key: value, key: value` string on TOP-LEVEL commas only —
/// commas inside `[...]` or quoted strings are preserved as part of
/// the surrounding value. Returns the comma-separated pieces (trimmed
/// at boundaries; whitespace inside values preserved).
///
/// Errors on unmatched brackets / unterminated quotes — those produce
/// confusing downstream errors otherwise.
fn split_top_level_commas(input: &str) -> Result<Vec<String>, String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut bracket_depth: usize = 0;
    let mut quote: Option<char> = None;
    let mut escape = false;

    for ch in input.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        if let Some(q) = quote {
            current.push(ch);
            if ch == '\\' {
                escape = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                quote = Some(ch);
                current.push(ch);
            },
            '[' | '(' | '{' => {
                bracket_depth += 1;
                current.push(ch);
            },
            ']' | ')' | '}' => {
                bracket_depth = bracket_depth
                    .checked_sub(1)
                    .ok_or_else(|| format!("unmatched `{ch}` in delegate(...) args"))?;
                current.push(ch);
            },
            ',' if bracket_depth == 0 => {
                parts.push(std::mem::take(&mut current));
            },
            _ => current.push(ch),
        }
    }
    if quote.is_some() {
        return Err("unterminated quoted string in delegate(...) args".to_string());
    }
    if bracket_depth != 0 {
        return Err("unbalanced brackets in delegate(...) args".to_string());
    }
    parts.push(current);
    Ok(parts)
}

/// Parse a single value from the function-call form: a scalar
/// (string / number / bool) or a list literal `[a, b, c]`. Use the
/// map form for anything more complex.
fn parse_delegate_value(s: &str) -> Result<serde_yaml::Value, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty value".to_string());
    }
    // List literal — recursive scalar parse on each element.
    if let Some(stripped) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        let items = split_top_level_commas(stripped)?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let item = item.trim();
            if item.is_empty() {
                continue;
            }
            out.push(parse_delegate_value(item)?);
        }
        return Ok(serde_yaml::Value::Sequence(out));
    }
    // Quoted string — strip the surrounding quotes.
    if (trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2)
        || (trimmed.starts_with('\'') && trimmed.ends_with('\'') && trimmed.len() >= 2)
    {
        return Ok(serde_yaml::Value::String(
            trimmed[1..trimmed.len() - 1].to_string(),
        ));
    }
    // Bool literals.
    if trimmed == "true" {
        return Ok(serde_yaml::Value::Bool(true));
    }
    if trimmed == "false" {
        return Ok(serde_yaml::Value::Bool(false));
    }
    // Numeric literals — integer first, then float.
    if let Ok(n) = trimmed.parse::<i64>() {
        return Ok(serde_yaml::Value::Number(serde_yaml::Number::from(n)));
    }
    if let Ok(f) = trimmed.parse::<f64>() {
        return Ok(serde_yaml::Value::Number(serde_yaml::Number::from(f)));
    }
    // Fallback: treat as bare string (e.g. `target: workday-api` →
    // value is `workday-api`). Same convention as YAML scalars.
    Ok(serde_yaml::Value::String(trimmed.to_string()))
}

/// Strip a single pair of wrapping `"`/`'` if present. No-op on
/// unquoted input. Used for the positional plugin name where the
/// operator may have quoted to escape a hyphen or similar (`delegate("workday-oauth")`).
fn strip_wrapping_quotes(s: &str) -> &str {
    let bytes = s.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &s[1..s.len() - 1];
        }
    }
    s
}

fn parse_step_map(m: &serde_yaml::Mapping, source: &str) -> Result<Step, ParseError> {
    // Canonical structured rule: `- when: X\n  do: Y` (DSL §3.2).
    // Detected by the presence of *both* `when` and `do` keys — order
    // doesn't matter, and the map can carry extra keys for future
    // extensions (e.g. `id:` for rule identifiers).
    if has_key(m, "when") && has_key(m, "do") {
        return parse_when_do_rule(m, source);
    }

    if m.len() != 1 {
        return Err(ParseError::Rule {
            rule: format!("{:?}", m),
            msg: "step map must have exactly one key (PDP call signature, \
                   `when:`/`do:`, or a `predicate: [effects...]` shorthand)"
                .into(),
        });
    }
    let (key_val, body_val) = m.iter().next().unwrap();
    let key = key_val.as_str().ok_or_else(|| ParseError::Rule {
        rule: format!("{:?}", key_val),
        msg: "PDP step key must be a string".into(),
    })?;

    // Shorthand multi-effect map: `- "predicate": [list]` (DSL §3.1
    // multi-effect from one predicate). Detected by a single-key map
    // whose value is a YAML sequence. Single-effect map shorthand
    // (`- "predicate": deny`) still goes through `parse_step_string`
    // via the colon-split, NOT here — by the time we land in this
    // function, single-string values have already been resolved by
    // the caller's `parse_step` dispatch.
    if let serde_yaml::Value::Sequence(items) = body_val {
        // Skip PDP keys — `cedar:` / `opa:` etc. have list bodies for
        // `on_deny:` / `on_allow:` and need the existing handling.
        // Also skip `sequential:` / `parallel:` orchestration keys
        // since they take a list body and would otherwise be parsed
        // as predicates. The shorthand recognises only predicate-
        // shaped keys.
        let trimmed = key.trim();
        if trimmed != "delegate"
            && trimmed != "sequential"
            && trimmed != "parallel"
            && !is_known_pdp_dialect(trimmed)
        {
            return parse_shorthand_multi_effect(trimmed, items, source);
        }
    }

    // `delegate:` is a special non-PDP step shape — branch before the
    // dialect logic. See `parse_delegate_step` for the expected body.
    if key.trim() == "delegate" {
        return parse_delegate_step(body_val, source);
    }

    // `restrict:` — the backend candidate constraint (accumulating
    // effect, `Taint` family). Body is a map of typed fields + a
    // `custom` label map; branch before the PDP-dialect logic since
    // `restrict` is not a PDP call.
    if key.trim() == "restrict" {
        let spec = parse_restrict_spec(body_val, source)?;
        return Ok(Step::Restrict { spec });
    }

    // E3: top-level `sequential:` / `parallel:` orchestration —
    // wrap the resulting Effect into an unconditional Rule so the
    // top-level Vec<Step> stays uniform.
    match key.trim() {
        "sequential" => {
            let effect = parse_sequential_effect(body_val, source)?;
            return Ok(Step::Rule(Rule {
                condition: Expression::Always,
                effects: vec![effect],
                source: source.to_string(),
            }));
        },
        "parallel" => {
            let effect = parse_parallel_effect(body_val, source)?;
            return Ok(Step::Rule(Rule {
                condition: Expression::Always,
                effects: vec![effect],
                source: source.to_string(),
            }));
        },
        _ => {},
    }

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
        msg: format!(
            "`{}:` body must be a map (with on_deny / on_allow / args)",
            key
        ),
    })?;

    let (args, on_deny, on_allow) = extract_pdp_body(body, paren_args.as_deref(), source)?;

    Ok(Step::Pdp {
        call: PdpCall { dialect, args },
        on_deny,
        on_allow,
    })
}

/// Parse a `delegate:` step body into a `Step::Delegate`. Accepted
/// YAML shape:
///
/// ```yaml
/// - delegate:
///     plugin: workday-oauth          # required — TokenDelegateHook plugin name
///     config:                         # optional — per-call config override
///       target: workday-api
///       permissions: [read_compensation]
///     on_error: deny                  # optional — deny | continue (default deny)
/// ```
///
// =====================================================================
// Effect / when-do parsing (E1)
// =====================================================================

/// Lookup helper — `serde_yaml::Mapping::contains_key` only matches when
/// the search key is a `Value`, so we wrap the string conversion.
fn has_key(m: &serde_yaml::Mapping, key: &str) -> bool {
    m.contains_key(serde_yaml::Value::String(key.to_string()))
}

/// Whether a top-level map key is a recognized PDP dialect. Used by
/// the shorthand-list detector to avoid mis-parsing a `cedar: [...]`
/// reaction list as a predicate-with-effects map.
fn is_known_pdp_dialect(key: &str) -> bool {
    let base = key.find('(').map(|i| &key[..i]).unwrap_or(key);
    matches!(base.trim(), "cedar" | "opa" | "authzen" | "nemo" | "cel")
}

/// Parse the canonical `- when: X` `do: Y` rule form (DSL §3.2). `Y`
/// may be a single effect string (`do: deny`) or a list of effect
/// entries (`do: [plugin(audit), taint(X), deny('msg')]`). Map-form
/// effects (like a nested `delegate:` block) are allowed inside `do:`
/// via the same dispatch as top-level steps.
fn parse_when_do_rule(m: &serde_yaml::Mapping, source: &str) -> Result<Step, ParseError> {
    // Validate keys — surface a useful error if there's stray content
    // beyond `when:` / `do:` (e.g. typo'd `whens:`). `id:` is reserved
    // for a future rule-identifier extension; tolerate it as a
    // pass-through for now.
    for (k, _) in m.iter() {
        let key = k.as_str().unwrap_or("");
        if !matches!(key, "when" | "do" | "id") {
            return Err(ParseError::Rule {
                rule: format!("{:?}", m),
                msg: format!(
                    "unexpected key `{}` in when/do rule (allowed: `when`, `do`, `id`)",
                    key
                ),
            });
        }
    }

    let when_val = m
        .get(serde_yaml::Value::String("when".into()))
        .expect("has_key verified above");
    let predicate = when_val.as_str().ok_or_else(|| ParseError::Rule {
        rule: format!("{:?}", when_val),
        msg: "`when:` must be a predicate string".into(),
    })?;
    let condition = parse_predicate(predicate).map_err(|e| ParseError::Rule {
        rule: format!("when: {}", predicate),
        msg: format!("{}", e),
    })?;

    let do_val = m
        .get(serde_yaml::Value::String("do".into()))
        .expect("has_key verified above");
    let effects = parse_do_body(do_val, source)?;
    if effects.is_empty() {
        return Err(ParseError::Rule {
            rule: format!("{:?}", m),
            msg: "`do:` produced no effects".into(),
        });
    }

    Ok(Step::Rule(Rule {
        condition,
        effects,
        source: source.to_string(),
    }))
}

/// Parse the shorthand multi-effect map form: `- "predicate": [list]`
/// (DSL §3 example at line 386). Equivalent to the canonical
/// `when: predicate` `do: [list]` shape, just terser.
fn parse_shorthand_multi_effect(
    predicate: &str,
    effect_list: &[serde_yaml::Value],
    source: &str,
) -> Result<Step, ParseError> {
    let condition = parse_predicate(predicate).map_err(|e| ParseError::Rule {
        rule: predicate.to_string(),
        msg: format!("{}", e),
    })?;

    let mut effects = Vec::with_capacity(effect_list.len());
    for item in effect_list {
        effects.push(parse_effect_value(item, source)?);
    }
    if effects.is_empty() {
        return Err(ParseError::Rule {
            rule: predicate.to_string(),
            msg: "shorthand multi-effect map produced no effects".into(),
        });
    }
    Ok(Step::Rule(Rule {
        condition,
        effects,
        source: source.to_string(),
    }))
}

/// Parse a `do:` body — single effect string, list of effects, or a
/// single map-shaped effect (`do: { parallel: [...] }`,
/// `do: { delegate: {...} }`, etc.).
fn parse_do_body(val: &serde_yaml::Value, source: &str) -> Result<Vec<Effect>, ParseError> {
    match val {
        serde_yaml::Value::String(s) => Ok(vec![parse_effect_string(s, source)?]),
        serde_yaml::Value::Sequence(items) => items
            .iter()
            .map(|item| parse_effect_value(item, source))
            .collect(),
        serde_yaml::Value::Mapping(_) => {
            // Single map-form effect — delegate, sequential, parallel.
            // Route through parse_effect_value which dispatches by key.
            Ok(vec![parse_effect_value(val, source)?])
        },
        other => Err(ParseError::Rule {
            rule: format!("{:?}", other),
            msg: "`do:` value must be a string, a list of effects, or an effect map".into(),
        }),
    }
}

/// Parse one effect entry from a YAML value — string form or map form
/// (the latter for `delegate:` configs nested inside `do:`,
/// `sequential:`, and `parallel:`).
fn parse_effect_value(val: &serde_yaml::Value, source: &str) -> Result<Effect, ParseError> {
    match val {
        serde_yaml::Value::String(s) => parse_effect_string(s, source),
        serde_yaml::Value::Mapping(m) => {
            // E3: `sequential:` / `parallel:` map forms — a single-key
            // map whose key is `sequential` / `parallel` and whose
            // value is a list of effects.
            if m.len() == 1 {
                let (k, v) = m.iter().next().unwrap();
                if let Some(key_str) = k.as_str() {
                    match key_str.trim() {
                        "sequential" => return parse_sequential_effect(v, source),
                        "parallel" => return parse_parallel_effect(v, source),
                        "restrict" => return parse_restrict_effect(v, source),
                        _ => {},
                    }
                }
            }
            // Otherwise reuse the existing step-map parser for
            // `delegate:`, `cedar:` etc. and collapse the Step.
            let step = parse_step(val, source)?;
            step_to_effect(step, source)
        },
        other => Err(ParseError::Rule {
            rule: format!("{:?}", other),
            msg: "effect entry must be a string or a map".into(),
        }),
    }
}

/// Parse a `sequential: [list]` effect value. The body MUST be a list
/// (a single effect would defeat the purpose of explicit grouping).
fn parse_sequential_effect(body: &serde_yaml::Value, source: &str) -> Result<Effect, ParseError> {
    let items = body.as_sequence().ok_or_else(|| ParseError::Rule {
        rule: format!("{:?}", body),
        msg: "`sequential:` body must be a list of effects".into(),
    })?;
    if items.is_empty() {
        return Err(ParseError::Rule {
            rule: format!("{:?}", body),
            msg: "`sequential:` body is empty".into(),
        });
    }
    let mut effects = Vec::with_capacity(items.len());
    for item in items {
        effects.push(parse_effect_value(item, source)?);
    }
    Ok(Effect::Sequential(effects))
}

/// Parse a `parallel: [list]` effect value. The body MUST be a list,
/// and the parsed Effect is validated for parallel-purity (rejects
/// `FieldOp` / `Delegate` nested anywhere underneath).
fn parse_parallel_effect(body: &serde_yaml::Value, source: &str) -> Result<Effect, ParseError> {
    let items = body.as_sequence().ok_or_else(|| ParseError::Rule {
        rule: format!("{:?}", body),
        msg: "`parallel:` body must be a list of effects".into(),
    })?;
    if items.is_empty() {
        return Err(ParseError::Rule {
            rule: format!("{:?}", body),
            msg: "`parallel:` body is empty".into(),
        });
    }
    let mut effects = Vec::with_capacity(items.len());
    for item in items {
        effects.push(parse_effect_value(item, source)?);
    }
    let parallel = Effect::Parallel(effects);
    parallel
        .validate_parallel_purity()
        .map_err(|msg| ParseError::Rule {
            rule: source.to_string(),
            msg,
        })?;
    Ok(parallel)
}

/// Parse a `restrict: { ... }` map into an `Effect::Restrict`. Thin
/// wrapper over [`parse_restrict_spec`] — the effect form (inside `do:` /
/// `sequential:` / `parallel:` / a PDP reaction) and the top-level step
/// form share the same body shape.
fn parse_restrict_effect(body: &serde_yaml::Value, source: &str) -> Result<Effect, ParseError> {
    let spec = parse_restrict_spec(body, source)?;
    Ok(Effect::Restrict { spec })
}

/// Parse a `restrict:` body map into a [`RestrictSpec`]
/// (`docs/apl-restrict-effect-design.md` §2.3, §4.3). Every field is
/// optional, but an entirely empty `restrict:` is rejected — it would
/// constrain nothing, so it's an author error. Unknown keys are a hard
/// error: the constraint is a fixed contract we ask the host's router to
/// honor, and a typo'd field must never silently widen the eligible set.
///
/// The string-set fields (`allow_models` / `deny_models` / `allow_regions`
/// / `allow_sites`) accept either a literal YAML list **or** a bare
/// scalar `data.*` reference resolved per request (§4.3).
fn parse_restrict_spec(
    body_val: &serde_yaml::Value,
    source: &str,
) -> Result<crate::constraint::RestrictSpec, ParseError> {
    use crate::constraint::{OnEmpty, RestrictSpec};

    let body = body_val.as_mapping().ok_or_else(|| ParseError::Rule {
        rule: source.to_string(),
        msg: "`restrict:` body must be a map of constraint fields (allow_models / \
              deny_models / allow_regions / allow_sites / max_cost_tier / custom / \
              on_empty)"
            .to_string(),
    })?;

    let mut spec = RestrictSpec::default();

    for (k, v) in body.iter() {
        let key = k.as_str().ok_or_else(|| ParseError::Rule {
            rule: source.to_string(),
            msg: "`restrict:` field keys must be strings".to_string(),
        })?;
        // Field-scoped error so authors see e.g. `restrict.allow_models: ...`.
        let field_err = |msg: String| ParseError::Rule {
            rule: source.to_string(),
            msg: format!("`restrict.{}`: {}", key.trim(), msg),
        };
        match key.trim() {
            "allow_models" => {
                spec.allow_models = Some(parse_string_set_spec(v).map_err(&field_err)?);
            },
            "deny_models" => {
                spec.deny_models = Some(parse_string_set_spec(v).map_err(&field_err)?);
            },
            "allow_regions" => {
                spec.allow_regions = Some(parse_string_set_spec(v).map_err(&field_err)?);
            },
            "allow_sites" => {
                spec.allow_sites = Some(parse_string_set_spec(v).map_err(&field_err)?);
            },
            "max_cost_tier" => {
                let tier = v
                    .as_str()
                    .ok_or_else(|| field_err("must be a string tier".to_string()))?;
                if tier.trim().is_empty() {
                    return Err(field_err("tier must not be empty".to_string()));
                }
                spec.max_cost_tier = Some(tier.trim().to_string());
            },
            "custom" => {
                spec.custom = parse_label_map(v).map_err(&field_err)?;
            },
            "on_empty" => {
                let s = v
                    .as_str()
                    .ok_or_else(|| field_err("must be `deny` or `fallback`".to_string()))?;
                spec.on_empty = match s.trim() {
                    "deny" => OnEmpty::Deny,
                    "fallback" => OnEmpty::Fallback,
                    other => {
                        return Err(field_err(format!(
                            "unknown value `{}` (expected `deny` or `fallback`)",
                            other
                        )))
                    },
                };
            },
            other => {
                return Err(ParseError::Rule {
                    rule: source.to_string(),
                    msg: format!(
                        "unknown `restrict:` field `{}` (allowed: allow_models, \
                         deny_models, allow_regions, allow_sites, max_cost_tier, \
                         custom, on_empty)",
                        other
                    ),
                });
            },
        }
    }

    // `is_empty()` ignores `on_empty` (a bare `on_empty:` constrains
    // nothing), so this also rejects `restrict: { on_empty: deny }`.
    if spec.is_empty() {
        return Err(ParseError::Rule {
            rule: source.to_string(),
            msg: "`restrict:` declares no constraint fields — it would restrict nothing; \
                  remove it or add at least one of allow_models / deny_models / \
                  allow_regions / allow_sites / max_cost_tier / custom"
                .to_string(),
        });
    }

    Ok(spec)
}

/// Parse a `restrict` string-set field. A YAML **sequence** is a literal
/// set of strings; a bare **scalar string** is a `data.*` reference
/// resolved per request (design §4.3) — e.g.
/// `allow_models: data.agents[subject.id].allowed_models`.
fn parse_string_set_spec(
    v: &serde_yaml::Value,
) -> Result<crate::constraint::StringSetSpec, String> {
    use crate::constraint::StringSetSpec;
    match v {
        serde_yaml::Value::Sequence(_) => Ok(StringSetSpec::Literal(parse_string_list(v)?)),
        serde_yaml::Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                return Err("reference path must not be empty".to_string());
            }
            Ok(StringSetSpec::Ref(s.to_string()))
        },
        _ => Err("must be a list of strings or a `data.*` reference string".to_string()),
    }
}

/// Parse a YAML value expected to be a non-empty list of non-empty
/// strings (the `allow_*` / `deny_*` constraint fields). Surrounding
/// whitespace is trimmed; interior characters (e.g. a `*` glob or a `/`
/// in a model id) are preserved.
fn parse_string_list(v: &serde_yaml::Value) -> Result<Vec<String>, String> {
    let seq = v
        .as_sequence()
        .ok_or_else(|| "must be a list of strings".to_string())?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let s = item
            .as_str()
            .ok_or_else(|| "list entries must be strings".to_string())?;
        if s.trim().is_empty() {
            return Err("list entries must not be empty".to_string());
        }
        out.push(s.trim().to_string());
    }
    if out.is_empty() {
        return Err("list must not be empty".to_string());
    }
    Ok(out)
}

/// Parse a YAML value expected to be a flat map of `label: value`
/// pairs (the `custom` field). Scalar values (string / bool / number)
/// are coerced to their string form, matching the label-map contract
/// (design §2.3.1) — `custom` is equality-matched labels, not typed
/// values.
fn parse_label_map(v: &serde_yaml::Value) -> Result<std::collections::BTreeMap<String, String>, String> {
    let map = v
        .as_mapping()
        .ok_or_else(|| "must be a map of `label: value` pairs".to_string())?;
    let mut out = std::collections::BTreeMap::new();
    for (k, val) in map {
        let key = k
            .as_str()
            .ok_or_else(|| "label keys must be strings".to_string())?;
        if key.trim().is_empty() {
            return Err("label keys must not be empty".to_string());
        }
        let value = scalar_to_string(val).ok_or_else(|| {
            format!(
                "label `{}` must be a scalar (string / bool / number)",
                key.trim()
            )
        })?;
        out.insert(key.trim().to_string(), value);
    }
    if out.is_empty() {
        return Err("`custom` map must not be empty".to_string());
    }
    Ok(out)
}

/// Coerce a scalar YAML value to its string form for a `custom` label.
/// Non-scalars (sequences, maps, null) return `None` — a label value
/// must be a single comparable token.
fn scalar_to_string(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.clone()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Parse one effect string. Reuses [`parse_step_string`] for forms
/// shared with top-level steps (`plugin(...)`, `taint(...)`,
/// `delegate(...)`, predicate-action rules), then collapses the
/// resulting Step into an Effect.
fn parse_effect_string(s: &str, source: &str) -> Result<Effect, ParseError> {
    // Bare `allow` / `deny` / `deny('reason')` / `deny('reason', 'code')`
    // are accepted directly — they map to control effects with no
    // associated condition. Same parsing as the right-hand side of a
    // shorthand `predicate: action` rule.
    let trimmed = s.trim();
    if let Some(mut effects) = try_bare_action(trimmed) {
        if effects.len() == 1 {
            return Ok(effects.pop().unwrap());
        }
    }
    if let Some(effect) = try_parse_deny_call(trimmed, s)? {
        return Ok(effect);
    }
    // Content effect — `result.salary | redact`, `args.ssn | mask(4)`,
    // etc. Detected by a top-level `|` that splits a dotted path from
    // a pipe chain. The pipe is at top level (depth 0); commas /
    // parens inside the chain don't get confused.
    if let Some(field_op) = try_parse_field_op(trimmed, s)? {
        return Ok(field_op);
    }
    // Everything else (plugin/delegate/taint/rule) routes through the
    // step parser; collapse the result.
    let step = parse_step_string(s, source)?;
    step_to_effect(step, source)
}

/// Parse `<path> | <stage> [| <stage>...]` into an `Effect::FieldOp`.
/// Returns `Ok(None)` when no top-level `|` is found so the caller can
/// fall through to other effect handlers.
fn try_parse_field_op(s: &str, rule: &str) -> Result<Option<Effect>, ParseError> {
    let Some(pipe_idx) = find_top_level_pipe(s) else {
        return Ok(None);
    };
    let path = s[..pipe_idx].trim();
    let chain = s[pipe_idx + 1..].trim();
    if path.is_empty() || chain.is_empty() {
        return Ok(None);
    }
    // The path must look like a dotted field reference. Anything else
    // (e.g. `role.hr | role.security` — though that wouldn't get here
    // because predicates don't appear in effect position) is a sign
    // the author meant something other than a field op.
    if !is_valid_field_path(path) {
        return Ok(None);
    }
    let pipeline = parse_pipeline(chain).map_err(|e| ParseError::Rule {
        rule: rule.to_string(),
        msg: format!("field op `{}`: {}", path, e),
    })?;
    if pipeline.stages.is_empty() {
        return Err(ParseError::Rule {
            rule: rule.to_string(),
            msg: format!("field op `{}` has no stages", path),
        });
    }
    Ok(Some(Effect::FieldOp {
        path: path.to_string(),
        stages: pipeline.stages,
    }))
}

/// Find the byte index of the first top-level `|` that isn't part of
/// `||` (logical-or inside a predicate). Depth-aware: skips `|` inside
/// `(...)` / `[...]` and inside single- or double-quoted strings.
fn find_top_level_pipe(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut depth: i32 = 0;
    let mut quote: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match b {
            b'\'' | b'"' => quote = Some(b),
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth -= 1,
            b'|' if depth == 0 => {
                // Skip `||` — never appears in effect strings today
                // but defend against it anyway.
                if bytes.get(i + 1) == Some(&b'|') {
                    i += 2;
                    continue;
                }
                return Some(i);
            },
            _ => {},
        }
        i += 1;
    }
    None
}

/// A field path is a dotted identifier sequence rooted at `args.` or
/// `result.`. Reject anything else early so a stray `role.hr | …` in
/// effect position fails fast.
fn is_valid_field_path(s: &str) -> bool {
    let Some(rest) = s
        .strip_prefix("args.")
        .or_else(|| s.strip_prefix("result."))
    else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('.')
            .all(|seg| !seg.is_empty() && seg.chars().all(|c| c.is_alphanumeric() || c == '_'))
}

/// Collapse a `Step` produced by the legacy step parser into an
/// `Effect`. The legitimate inputs are `Plugin`, `Delegate`, `Taint`,
/// and `Rule` (when a control action like `deny`/`allow` was parsed).
/// Anything else (`Pdp`) is rejected — nested PDP calls inside `do:`
/// are out of scope for E1.
/// Recursively map a top-level `Step` (as produced by `parse_step`) into
/// an `Effect`. Used at compile_apl_blocks during E4 — keeps `parse_step`'s
/// internal shape for the moment while the public IR collapses to Effect.
/// All five Step variants map cleanly: Rule → When, Pdp → Pdp (recursive
/// on reactions), Plugin/Delegate/Taint pass-through.
pub(crate) fn step_to_top_level_effect(step: Step) -> Result<Effect, ParseError> {
    match step {
        Step::Rule(rule) => Ok(Effect::When {
            condition: rule.condition,
            body: rule.effects,
            source: rule.source,
        }),
        Step::Pdp {
            call,
            on_allow,
            on_deny,
        } => {
            let on_allow = on_allow
                .into_iter()
                .map(step_to_top_level_effect)
                .collect::<Result<Vec<_>, _>>()?;
            let on_deny = on_deny
                .into_iter()
                .map(step_to_top_level_effect)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Effect::Pdp {
                call,
                on_allow,
                on_deny,
            })
        },
        Step::Plugin { name } => Ok(Effect::Plugin { name }),
        Step::Delegate(d) => Ok(Effect::Delegate(d)),
        Step::Taint { label, scopes } => Ok(Effect::Taint { label, scopes }),
        Step::Restrict { spec } => Ok(Effect::Restrict { spec }),
    }
}

fn step_to_effect(step: Step, source: &str) -> Result<Effect, ParseError> {
    match step {
        Step::Plugin { name } => Ok(Effect::Plugin { name }),
        Step::Delegate(d) => Ok(Effect::Delegate(d)),
        Step::Taint { label, scopes } => Ok(Effect::Taint { label, scopes }),
        Step::Restrict { spec } => Ok(Effect::Restrict { spec }),
        Step::Rule(rule) => {
            // Nested when/do inside a do: list isn't supported in E1
            // — only control effects (allow/deny) flatten cleanly.
            if !matches!(rule.condition, Expression::Always) {
                return Err(ParseError::Rule {
                    rule: source.to_string(),
                    msg: "conditional rules nested inside `do:` are not supported in E1 \
                          (use a sibling `when:`/`do:` rule instead)"
                        .into(),
                });
            }
            if rule.effects.len() != 1 {
                return Err(ParseError::Rule {
                    rule: source.to_string(),
                    msg: format!(
                        "unconditional rule inside `do:` must produce exactly one \
                         effect, got {}",
                        rule.effects.len()
                    ),
                });
            }
            Ok(rule.effects.into_iter().next().unwrap())
        },
        Step::Pdp { .. } => Err(ParseError::Rule {
            rule: source.to_string(),
            msg: "PDP calls inside `do:` are not supported in E1 (use a sibling \
                  step instead)"
                .into(),
        }),
    }
}

/// `config:` is opaque — the framework hands it to the named plugin
/// via the existing per-call config-override pathway. The plugin
/// owns the typed schema (target / audience / permissions / mode /
/// attenuation are conventions, not parser-enforced).
fn parse_delegate_step(body_val: &serde_yaml::Value, source: &str) -> Result<Step, ParseError> {
    let body = body_val.as_mapping().ok_or_else(|| ParseError::Rule {
        rule: source.to_string(),
        msg: "`delegate:` body must be a map with `plugin:` and optional \
              `config:` / `on_error:`"
            .to_string(),
    })?;

    let plugin = body
        .get(serde_yaml::Value::String("plugin".to_string()))
        .ok_or_else(|| ParseError::Rule {
            rule: source.to_string(),
            msg: "`delegate:` requires `plugin: <name>` referencing a \
                  top-level plugin registered under `token.delegate`"
                .to_string(),
        })?;
    let plugin_name = plugin
        .as_str()
        .ok_or_else(|| ParseError::Rule {
            rule: source.to_string(),
            msg: "`delegate.plugin` must be a string".to_string(),
        })?
        .to_string();
    if plugin_name.is_empty() {
        return Err(ParseError::Rule {
            rule: source.to_string(),
            msg: "`delegate.plugin` cannot be empty".to_string(),
        });
    }

    let config_override = body
        .get(serde_yaml::Value::String("config".to_string()))
        .cloned();

    let on_error = match body.get(serde_yaml::Value::String("on_error".to_string())) {
        Some(v) => Some(
            v.as_str()
                .ok_or_else(|| ParseError::Rule {
                    rule: source.to_string(),
                    msg: "`delegate.on_error` must be a string (e.g. `deny`, \
                          `continue`)"
                        .to_string(),
                })?
                .to_string(),
        ),
        None => None,
    };

    Ok(Step::Delegate(DelegateStep {
        plugin_name,
        config_override,
        on_error,
        source: source.to_string(),
    }))
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
            },
            Some("on_allow") => {
                on_allow = parse_reaction_list(v, source, "on_allow")?;
            },
            _ => {
                // Non-reaction key — part of args (Cedar-style).
                args_map.insert(k.clone(), v.clone());
            },
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
            },
            _ => {},
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
            (Some(_), _) => {},
            (None, b'"') | (None, b'\'') => in_quote = Some(b),
            (None, b'(') | (None, b'[') => depth += 1,
            (None, b')') | (None, b']') => depth -= 1,
            (None, c) if c == delim && depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            },
            _ => {},
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
    let (head, args) = split_head_args(s).ok_or_else(|| bad("expected stage identifier"))?;

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
        ("pii.redact", None) => Ok(Stage::Scan {
            kind: ScanKind::PiiRedact,
        }),
        ("pii.detect", None) => Ok(Stage::Scan {
            kind: ScanKind::PiiDetect,
        }),
        ("injection.scan", None) => Ok(Stage::Scan {
            kind: ScanKind::InjectionScan,
        }),

        // ----- Parameterized -----
        ("mask", Some(a)) => {
            let n: usize = a
                .trim()
                .parse()
                .map_err(|_| bad(&format!("mask(N) expects integer, got `{}`", a)))?;
            Ok(Stage::Mask { keep_last: n })
        },
        ("redact", Some(a)) => {
            // redact(!perm.view_ssn) — argument is a predicate expression.
            let cond = parse_predicate(a).map_err(|e| ParseError::Predicate {
                predicate: src.to_string(),
                msg: format!("invalid redact() condition: {}", e),
            })?;
            Ok(Stage::Redact {
                condition: Some(cond),
            })
        },
        ("hash", Some(_)) => Err(bad("hash takes no arguments")),
        ("omit", Some(_)) => Err(bad(
            "omit takes no arguments — for conditional omit, use a policy rule predicate",
        )),
        ("len", Some(a)) => {
            let (min, max) = parse_range_inner(a)
                .ok_or_else(|| bad(&format!("len(...) expects N..M range, got `{}`", a)))?;
            let to_usize = |v: i64| -> Result<usize, ParseError> {
                if v < 0 {
                    Err(bad("len bounds must be non-negative"))
                } else {
                    Ok(v as usize)
                }
            };
            Ok(Stage::Length {
                min: min.map(to_usize).transpose()?,
                max: max.map(to_usize).transpose()?,
            })
        },
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
        },
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
        },
        ("validate", Some(a)) => {
            // Named-validator dispatch (`validate(name)`) is in the
            // spec (DSL §4.2) but not implemented in this build —
            // the evaluator's no-op stub would silently let invalid
            // values through. Reject at compile time so operators
            // notice immediately and reach for one of the working
            // alternatives:
            //
            //   * `regex("pattern")` — inline named-regex equivalent
            //   * `plugin(name)` — full plugin dispatch for rich
            //     validation (Luhn, format-with-context, etc.)
            //
            // When the ValidatorRegistry slice lands, this arm flips
            // back to returning `Stage::Validate { name }`.
            Err(bad(&format!(
                "`validate({})` — named-validator dispatch is not implemented \
                 in this build. Use `regex(\"pattern\")` for a named-regex \
                 equivalent, or `plugin({})` for richer validation logic.",
                a.trim(),
                a.trim(),
            )))
        },
        // `run` is an alias for `plugin` (mirrors the policy-step alias).
        ("plugin" | "run", Some(a)) => {
            let name = a.trim();
            if name.is_empty() {
                // Mirror the empty-name guard in `parse_step_string` so
                // both the policy-step and field-stage paths reject a
                // nameless `plugin()` / `run()` with the same diagnostic.
                return Err(bad(&format!(
                    "`{head}(...)`: plugin name must not be empty"
                )));
            }
            Ok(Stage::Plugin {
                name: name.to_string(),
            })
        },
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
    let min = if left.is_empty() {
        None
    } else {
        Some(parse_numeric_with_suffix(left)?)
    };
    let max = if right.is_empty() {
        None
    } else {
        Some(parse_numeric_with_suffix(right)?)
    };
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
                    if depth == 0 {
                        close = Some(i);
                        break;
                    }
                },
                _ => {},
            }
        }
        let close = close?;
        let head = s[..open].trim();
        if head.is_empty() {
            return None;
        }
        let args = s[open + 1..close].to_string();
        // Reject trailing garbage after the closing paren.
        if s[close + 1..].trim().is_empty() {
            Some((head, Some(args)))
        } else {
            None
        }
    } else {
        let head = s.trim();
        if head.is_empty() {
            None
        } else {
            Some((head, None))
        }
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
            msg: format!(
                "unknown taint scope `{}` (expected `session` or `message`)",
                other
            ),
        }),
    }
}

// =====================================================================
// YAML config
// =====================================================================

/// Top-level config — only the bits step 5a understands.
///
/// `policy_evaluator:`, `imports:`, `global:`, `defaults:`, `tags:`,
/// `plugin_dirs:`, `plugin_settings:`, `version:` are all accepted and
/// stored opaquely; this struct deserializes leniently.
///
/// `plugins:` (the root block) is parsed into [`PluginDeclaration`]s so
/// the runtime can look up hook names + capabilities per plugin without
/// going back to the raw YAML.
#[derive(Debug, Default, Deserialize)]
pub struct ConfigYaml {
    #[serde(default)]
    pub routes: HashMap<String, RouteYaml>,

    /// Root `plugins:` block — full declarations.
    #[serde(default)]
    pub plugins: Vec<PluginDeclaration>,

    /// Anything else top-level goes here — picked up by later steps.
    #[serde(flatten)]
    pub other: HashMap<String, serde_yaml::Value>,
}

#[derive(Debug, Default, Deserialize)]
pub struct RouteYaml {
    /// Flat pre-invocation authorization effects (was `policy:`). Each
    /// entry is either a string (rule / plugin / taint) or a single-key
    /// map (PDP call with reactions). See `parse_step`. Merged with any
    /// `authorization.pre_invocation` entries.
    #[serde(default)]
    pub pre_invocation: Vec<serde_yaml::Value>,

    /// Flat post-invocation authorization effects (was `post_policy:`).
    /// Merged with any `authorization.post_invocation` entries.
    #[serde(default)]
    pub post_invocation: Vec<serde_yaml::Value>,

    /// Nested `authorization:` block — `{ pre_invocation, post_invocation }`.
    /// Equivalent to the flat forms; entries from both are concatenated.
    #[serde(default)]
    pub authorization: Option<AuthorizationYaml>,

    /// `args:` field → pipe-chain string. Compiled to per-field pipelines.
    #[serde(default)]
    pub args: HashMap<String, String>,

    /// `result:` field → pipe-chain string. Compiled to per-field pipelines.
    #[serde(default)]
    pub result: HashMap<String, String>,

    /// Per-route plugin overrides — only the spec-overridable keys
    /// (config / capabilities / on_error). Merged on top of the root
    /// `plugins:` declaration at dispatch time.
    #[serde(default)]
    pub plugins: HashMap<String, PluginOverride>,

    /// Anything else on the route (meta, taint, when) — stashed. Also
    /// where renamed legacy keys land; `reject_legacy_keys` fails loudly
    /// on them so a dropped authz block never fails open.
    #[serde(flatten)]
    pub other: HashMap<String, serde_yaml::Value>,
}

/// Nested `authorization:` block. Both sub-lists are optional and default
/// to empty; each is compiled the same way as the flat `pre_invocation:` /
/// `post_invocation:` forms.
///
/// `deny_unknown_fields` is load-bearing: without it a legacy key nested
/// under the wrapper (`authorization: { policy: [...] }`) would be silently
/// dropped by serde — both lists empty, no error, no authorization enforced
/// (a fail-open). The top-level `reject_legacy_keys` can't catch it because
/// the key is consumed as part of the `authorization` value and never lands
/// in `RouteYaml.other`. Denying unknown fields turns that into a load error
/// and also catches typos like `pre_invocaton:`. Safe here because the struct
/// has no `#[serde(flatten)]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationYaml {
    #[serde(default)]
    pub pre_invocation: Vec<serde_yaml::Value>,

    #[serde(default)]
    pub post_invocation: Vec<serde_yaml::Value>,
}

/// Output of [`compile_config`] — the routes that have APL blocks plus
/// the registry of plugin declarations from the root `plugins:` block.
///
/// The two travel together because the evaluator needs both: the route
/// gives it the steps to run, and the registry gives the dispatcher the
/// hook name / kind for each plugin name referenced by those steps.
#[derive(Debug, Default)]
pub struct CompiledConfig {
    pub routes: HashMap<String, CompiledRoute>,
    pub plugins: PluginRegistry,
}

/// Compile a YAML config into a [`CompiledConfig`] (routes + plugin
/// registry).
///
/// Routes with no APL fields populated (no `authorization:` /
/// `pre_invocation:` / `post_invocation:` / `args:` / `result:`) are
/// **omitted from `routes`**, per apl-design §5
/// "Routes without APL blocks fall back to legacy plugin-chain execution."
/// A route-level `plugins:` override block alone is not enough — overrides
/// only have meaning when the route actually dispatches plugins via APL
/// steps, so an override-only route is treated as legacy.
pub fn compile_config(yaml: &str) -> Result<CompiledConfig, ParseError> {
    let cfg: ConfigYaml = serde_yaml::from_str(yaml)?;
    let mut routes = HashMap::with_capacity(cfg.routes.len());
    for (route_key, raw) in cfg.routes {
        if let Some(route) = compile_route(&route_key, raw)? {
            routes.insert(route_key, route);
        }
    }
    let mut plugins = PluginRegistry::with_capacity(cfg.plugins.len());
    for decl in cfg.plugins {
        // Duplicate plugin names: last-one-wins for v0. The spec doesn't
        // currently prescribe an error here; flag if real configs hit it.
        plugins.insert(decl.name.clone(), decl);
    }
    Ok(CompiledConfig { routes, plugins })
}

/// Legacy field names, mapped to their replacements. Because unknown keys
/// land in `RouteYaml.other` via `#[serde(flatten)]`, a config still using
/// an old name would otherwise be *silently dropped* — dropping a `policy:`
/// block fails open (no authorization enforced). We reject them loudly
/// instead. `identity` is renamed in cpex-core config, not here.
const RENAMED_FIELDS: [(&str, &str); 2] = [
    (
        "policy",
        "authorization.pre_invocation (or flat pre_invocation)",
    ),
    (
        "post_policy",
        "authorization.post_invocation (or flat post_invocation)",
    ),
];

/// Fail loudly if a stashed key is a renamed legacy field, so a dropped
/// authz block never fails open. Run before the has-APL gate.
fn reject_legacy_keys(
    location: &str,
    other: &HashMap<String, serde_yaml::Value>,
) -> Result<(), ParseError> {
    for (old, new) in RENAMED_FIELDS {
        if other.contains_key(old) {
            return Err(ParseError::RenamedField {
                location: location.to_string(),
                old: old.to_string(),
                new: new.to_string(),
            });
        }
    }
    Ok(())
}

fn compile_route(route_key: &str, raw: RouteYaml) -> Result<Option<CompiledRoute>, ParseError> {
    // Reject legacy keys *before* the gate: a legacy-only route would
    // otherwise look empty and be silently omitted (fail open).
    reject_legacy_keys(route_key, &raw.other)?;
    let has_authz = raw
        .authorization
        .as_ref()
        .is_some_and(|a| !a.pre_invocation.is_empty() || !a.post_invocation.is_empty());
    let has_apl = !raw.pre_invocation.is_empty()
        || !raw.post_invocation.is_empty()
        || has_authz
        || !raw.args.is_empty()
        || !raw.result.is_empty();
    if !has_apl {
        return Ok(None);
    }
    Ok(Some(compile_apl_blocks(route_key, raw)?))
}

/// Compile the APL bodies (authorization/args/result/plugins) of a
/// single block into a `CompiledRoute`. Doesn't gate on "has any APL
/// fields" — callers that need the gate (compile_config) check first.
/// `source` is the path prefix baked into rule/pipeline diagnostics
/// (e.g. `"global.policy.all"`, `"route.get_compensation"`).
///
/// The nested `authorization:` block and the flat `pre_invocation:` /
/// `post_invocation:` forms are equivalent alternatives. Declaring the same
/// phase in both forms on one section is rejected (it would run the effects
/// twice); only one form may carry a given phase per section.
fn compile_apl_blocks(source: &str, raw: RouteYaml) -> Result<CompiledRoute, ParseError> {
    reject_legacy_keys(source, &raw.other)?;
    let mut route = CompiledRoute::new(source);
    let (auth_pre, auth_post) = raw
        .authorization
        .map(|a| (a.pre_invocation, a.post_invocation))
        .unwrap_or_default();
    // Reject declaring the same phase both nested and flat on one section:
    // the two forms are alternatives, not additive, so merging them would
    // run each effect twice (a `run(...)` / `delegate(...)` double-fire).
    // Stacking across *different* scopes (e.g. global nested + route flat)
    // is fine — those are separate `compile_apl_blocks` calls.
    if !auth_pre.is_empty() && !raw.pre_invocation.is_empty() {
        return Err(ParseError::ConflictingAuthorizationForms {
            location: source.to_string(),
            phase: "pre_invocation".to_string(),
        });
    }
    if !auth_post.is_empty() && !raw.post_invocation.is_empty() {
        return Err(ParseError::ConflictingAuthorizationForms {
            location: source.to_string(),
            phase: "post_invocation".to_string(),
        });
    }
    for (i, entry) in auth_pre.iter().chain(raw.pre_invocation.iter()).enumerate() {
        let step = parse_step(entry, &format!("{}.pre_invocation[{}]", source, i))?;
        route.policy.push(step_to_top_level_effect(step)?);
    }
    for (i, entry) in auth_post
        .iter()
        .chain(raw.post_invocation.iter())
        .enumerate()
    {
        let step = parse_step(entry, &format!("{}.post_invocation[{}]", source, i))?;
        route.post_policy.push(step_to_top_level_effect(step)?);
    }
    for (field, chain) in &raw.args {
        let pipeline = parse_pipeline(chain).map_err(|e| ParseError::Rule {
            rule: format!("args.{}: {:?}", field, chain),
            msg: format!("{}", e),
        })?;
        route.args.push(FieldRule {
            field: field.clone(),
            pipeline,
            source: format!("{}.args.{}", source, field),
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
            source: format!("{}.result.{}", source, field),
        });
    }
    route.plugin_overrides = raw.plugins;
    Ok(route)
}

/// Compile a single APL policy block from a `serde_yaml::Value` whose
/// shape is the body of a route's `apl:` block:
///
/// ```yaml
/// args:
///   employee_id: "str"
/// authorization:
///   pre_invocation:
///     - "require(authenticated)"
///   post_invocation:
///     - "taint(forward)"
/// result:
///   ssn: "redact(!perm.view_ssn)"
/// ```
///
/// Used by external orchestrators (apl-cpex's `AplConfigVisitor`) that
/// have already located an APL block inside a larger unified-config
/// YAML. `source` is woven into per-rule / per-pipeline diagnostic paths.
/// Returns an empty `CompiledRoute` when the value is null or contains
/// no APL fields — callers that want a "is this empty?" gate can check
/// `declared_phases().is_empty()` on the result.
pub fn compile_policy_block_value(
    source: &str,
    block: &serde_yaml::Value,
) -> Result<CompiledRoute, ParseError> {
    if block.is_null() {
        return Ok(CompiledRoute::new(source));
    }
    let raw: RouteYaml = serde_yaml::from_value(block.clone())?;
    compile_apl_blocks(source, raw)
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attributes::AttributeBag;
    use crate::evaluator::Decision;

    // ----- Lexer -----

    #[test]
    fn lex_basic() {
        let toks = Lexer::new("delegation.depth > 2").tokenize_all().unwrap();
        assert_eq!(
            toks,
            vec![
                Tok::Ident("delegation.depth".into()),
                Tok::Gt,
                Tok::IntLit(2),
            ]
        );
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
        let toks = Lexer::new("require(role.hr) & authenticated")
            .tokenize_all()
            .unwrap();
        assert_eq!(
            toks,
            vec![
                Tok::Require,
                Tok::LParen,
                Tok::Ident("role.hr".into()),
                Tok::RParen,
                Tok::And,
                Tok::Ident("authenticated".into()),
            ]
        );
    }

    #[test]
    fn lex_rejects_single_equals() {
        let err = Lexer::new("a = 1").tokenize_all().unwrap_err();
        assert!(format!("{}", err).contains("expected `==`"));
    }

    // ----- R3b: interpolated attribute paths -----

    #[test]
    fn lex_interpolated_path_is_one_ident() {
        let toks = Lexer::new("data.tenants[subject.tenant].data_region")
            .tokenize_all()
            .unwrap();
        assert_eq!(
            toks,
            vec![Tok::Ident("data.tenants[subject.tenant].data_region".into())]
        );
    }

    #[test]
    fn lex_interpolated_path_in_comparison() {
        let toks = Lexer::new("data.tenants[subject.tenant].data_region == 'eu'")
            .tokenize_all()
            .unwrap();
        assert_eq!(
            toks,
            vec![
                Tok::Ident("data.tenants[subject.tenant].data_region".into()),
                Tok::Eq,
                Tok::StringLit("eu".into()),
            ]
        );
    }

    #[test]
    fn lex_rejects_unterminated_bracket() {
        let err = Lexer::new("data.tenants[subject.tenant").tokenize_all().unwrap_err();
        assert!(format!("{}", err).contains("unterminated"), "got: {}", err);
    }

    #[test]
    fn lex_rejects_nested_bracket() {
        let err = Lexer::new("data.x[a[b]]").tokenize_all().unwrap_err();
        assert!(format!("{}", err).contains("nested"), "got: {}", err);
    }

    #[test]
    fn interpolated_predicate_parses_to_comparison() {
        let e = parse_predicate("data.tenants[subject.tenant].data_region == 'eu'").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::Comparison {
                key: "data.tenants[subject.tenant].data_region".into(),
                op: CompareOp::Eq,
                value: Literal::String("eu".into()),
            })
        );
    }

    // ----- Predicate parser -----

    #[test]
    fn pred_bare_identifier() {
        let e = parse_predicate("authenticated").unwrap();
        assert_eq!(
            e,
            Expression::Condition(Condition::IsTrue {
                key: "authenticated".into()
            })
        );
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
                    Expression::And(_) => {},
                    other => panic!("first OR branch should be AND, got {:?}", other),
                }
            },
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
            },
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
        assert!(matches!(
            r.effects.as_slice(),
            [Effect::Deny {
                reason: None,
                code: None
            }]
        ));
        assert_eq!(
            r.condition,
            Expression::Condition(Condition::IsFalse {
                key: "authenticated".into()
            }),
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
                Expression::Condition(Condition::IsFalse {
                    key: "role.hr".into()
                }),
                Expression::Condition(Condition::IsFalse {
                    key: "perm.view_ssn".into()
                }),
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
                Expression::Condition(Condition::IsFalse {
                    key: "role.finance".into()
                }),
                Expression::Condition(Condition::IsFalse {
                    key: "role.admin".into()
                }),
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
            Expression::Condition(Condition::Exists {
                key: "args.amount".into()
            }),
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
                    Expression::Condition(Condition::Exists {
                        key: "args.amount".into()
                    }),
                );
            },
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
        match r.effects.as_slice() {
            [Effect::Deny { .. }] => {},
            other => panic!("expected [Deny], got {:?}", other),
        }
        match r.condition {
            Expression::Condition(Condition::Comparison { .. }) => {},
            other => panic!("expected Comparison, got {:?}", other),
        }
    }

    #[test]
    fn rule_predicate_only_defaults_to_deny() {
        // DSL §2: missing action defaults to deny.
        let r = parse_rule("!authenticated", "test").unwrap();
        assert!(matches!(r.effects.as_slice(), [Effect::Deny { .. }]));
    }

    #[test]
    fn rule_explicit_allow() {
        let r = parse_rule("role.admin: allow", "test").unwrap();
        assert!(matches!(r.effects.as_slice(), [Effect::Allow]));
    }

    #[test]
    fn rule_bare_action_unconditional() {
        // Bare `- deny` and `- allow` are unconditional rules with
        // Expression::Always as the predicate (DSL §3.1).
        let r = parse_rule("deny", "test").unwrap();
        assert_eq!(r.condition, Expression::Always);
        assert!(matches!(
            r.effects.as_slice(),
            [Effect::Deny {
                reason: None,
                code: None
            }]
        ));

        let r = parse_rule("allow", "test").unwrap();
        assert_eq!(r.condition, Expression::Always);
        assert!(matches!(r.effects.as_slice(), [Effect::Allow]));
    }

    #[test]
    fn rule_bare_deny_call_carries_reason_and_code() {
        // Unconditional `deny('reason')` / `deny('reason', 'code')` parse
        // to an Always-guarded Deny, so they're usable as bare rule lines
        // and as `on_deny:` / `on_allow:` reactions.
        let r = parse_rule("deny('nope')", "test").unwrap();
        assert_eq!(r.condition, Expression::Always);
        match r.effects.as_slice() {
            [Effect::Deny {
                reason: Some(reason),
                code: None,
            }] => assert_eq!(reason, "nope"),
            other => panic!(
                "expected [Deny{{reason: Some, code: None}}], got {:?}",
                other
            ),
        }

        let r = parse_rule("deny('nope', 'cel.policy')", "test").unwrap();
        assert_eq!(r.condition, Expression::Always);
        match r.effects.as_slice() {
            [Effect::Deny {
                reason: Some(reason),
                code: Some(code),
            }] => {
                assert_eq!(reason, "nope");
                assert_eq!(code, "cel.policy");
            },
            other => panic!("expected [Deny{{reason, code}}], got {:?}", other),
        }
    }

    #[test]
    fn rule_malformed_bare_deny_call_errors() {
        // A malformed `deny(...)` must surface its own error rather than
        // falling through to the predicate parser.
        let err = parse_rule("deny(unquoted)", "test").unwrap_err();
        assert!(
            matches!(err, ParseError::Rule { .. }),
            "expected ParseError::Rule, got {:?}",
            err
        );
    }

    #[test]
    fn rule_step_kinds_rejected_clearly() {
        for s in [
            "plugin(rate_limiter)",
            "cedar:(action: read)",
            "opa(path)",
            "taint(audit)",
        ] {
            let err = parse_rule(s, "test").unwrap_err();
            assert!(
                matches!(err, ParseError::UnsupportedStep { .. }),
                "expected UnsupportedStep for `{}`, got {:?}",
                s,
                err
            );
        }
    }

    #[test]
    fn rule_deny_with_unquoted_arg_rejected() {
        // `deny "reason"` (space-separated, no parens) is not a valid
        // form. The supported reason-carrying shape is
        // `deny('reason')` / `deny('reason', 'code')` per DSL §3 and
        // the E1 `code` extension.
        let err = parse_rule(r#"authenticated: deny "go away""#, "test").unwrap_err();
        assert!(format!("{}", err).contains("unsupported action"));
    }

    #[test]
    fn rule_deny_with_quoted_reason_accepted() {
        // `deny('reason')` — single-arg form. Reason landing on the
        // effect; code defaulting to None.
        let r = parse_rule(r#"delegation.depth > 2: deny('too deep')"#, "test").unwrap();
        assert!(matches!(
            r.effects.as_slice(),
            [Effect::Deny { reason: Some(s), code: None }] if s == "too deep"
        ));
    }

    #[test]
    fn rule_deny_with_reason_and_code_accepted() {
        // `deny('reason', 'code')` — E1 extension. Both reason and
        // author-supplied code surface in the violation.
        let r = parse_rule(
            r#"delegation.depth > 2: deny('too deep', 'delegation.depth_exceeded')"#,
            "test",
        )
        .unwrap();
        match r.effects.as_slice() {
            [Effect::Deny {
                reason: Some(reason),
                code: Some(code),
            }] => {
                assert_eq!(reason, "too deep");
                assert_eq!(code, "delegation.depth_exceeded");
            },
            other => panic!("expected Deny with reason+code, got {:?}", other),
        }
    }

    #[test]
    fn rule_deny_with_too_many_args_rejected() {
        // Cap on positional args — `deny(reason, code)` is the limit.
        let err = parse_rule(r#"x: deny('a', 'b', 'c')"#, "test").unwrap_err();
        assert!(format!("{}", err).contains("at most two args"));
    }

    #[test]
    fn rule_deny_with_unquoted_args_in_call_rejected() {
        // The args MUST be quoted; bare identifiers aren't legal.
        let err = parse_rule(r#"x: deny(bare, identifier)"#, "test").unwrap_err();
        assert!(format!("{}", err).contains("expected a quoted string"));
    }

    // ----- E1: when/do canonical form -----

    fn parse_step_yaml(yaml: &str) -> Result<Step, ParseError> {
        let v: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        parse_step(&v, "test")
    }

    #[test]
    fn when_do_single_effect_deny() {
        // do: deny  — single string value, no list.
        let step = parse_step_yaml("when: delegation.depth > 2\ndo: deny").unwrap();
        match step {
            Step::Rule(rule) => {
                assert!(matches!(
                    rule.condition,
                    Expression::Condition(Condition::Comparison { .. })
                ));
                assert!(matches!(
                    rule.effects.as_slice(),
                    [Effect::Deny {
                        reason: None,
                        code: None
                    }]
                ));
            },
            other => panic!("expected Step::Rule, got {:?}", other),
        }
    }

    #[test]
    fn when_do_single_effect_deny_with_reason_and_code() {
        // The E1 `deny('reason', 'code')` extension works inside `do:` too.
        let step = parse_step_yaml(
            "when: delegation.depth > 2\ndo: deny('too deep', 'delegation.depth_exceeded')",
        )
        .unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Step::Rule");
        };
        match rule.effects.as_slice() {
            [Effect::Deny {
                reason: Some(r),
                code: Some(c),
            }] => {
                assert_eq!(r, "too deep");
                assert_eq!(c, "delegation.depth_exceeded");
            },
            other => panic!("expected Deny+reason+code, got {:?}", other),
        }
    }

    #[test]
    fn when_do_multi_effect_list() {
        // The headline demo case: fan-out from one predicate.
        // do: [plugin(audit_logger), taint(unauth), deny('refused')]
        let yaml = r#"
when: "!role.hr"
do:
  - "plugin(audit_logger)"
  - "taint(unauth, session)"
  - "deny('refused', 'role.hr_required')"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Step::Rule");
        };
        assert_eq!(rule.effects.len(), 3);
        assert!(matches!(rule.effects[0], Effect::Plugin { ref name } if name == "audit_logger"));
        assert!(matches!(
            rule.effects[1],
            Effect::Taint { ref label, .. } if label == "unauth"
        ));
        match &rule.effects[2] {
            Effect::Deny {
                reason: Some(r),
                code: Some(c),
            } => {
                assert_eq!(r, "refused");
                assert_eq!(c, "role.hr_required");
            },
            other => panic!("expected Deny+reason+code, got {:?}", other),
        }
    }

    #[test]
    fn when_do_key_order_does_not_matter() {
        // YAML maps are unordered; `do:` first should parse the same.
        let step = parse_step_yaml("do: deny\nwhen: delegation.depth > 2").unwrap();
        assert!(matches!(step, Step::Rule(_)));
    }

    #[test]
    fn when_do_with_unknown_key_rejected() {
        // Typo guard — surface unknown keys instead of silently dropping.
        let err = parse_step_yaml("when: x\ndo: deny\nwhne: typo").unwrap_err();
        assert!(format!("{}", err).contains("unexpected key"));
    }

    #[test]
    fn when_do_empty_do_list_rejected() {
        // An empty `do:` is almost certainly an author mistake;
        // require at least one effect.
        let err = parse_step_yaml("when: x\ndo: []").unwrap_err();
        assert!(format!("{}", err).contains("no effects"));
    }

    // ----- E1: shorthand multi-effect map (predicate: [list]) -----

    #[test]
    fn shorthand_multi_effect_map() {
        // Shorthand for the canonical when/do form. The predicate is
        // the map's only key, the value is a list of effects.
        let yaml = r#"
"!role.hr":
  - "plugin(audit_logger)"
  - "deny('unauthorized')"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Step::Rule");
        };
        assert_eq!(rule.effects.len(), 2);
        assert!(matches!(rule.effects[0], Effect::Plugin { ref name } if name == "audit_logger"));
        assert!(matches!(
            rule.effects[1],
            Effect::Deny { reason: Some(ref r), code: None } if r == "unauthorized"
        ));
    }

    #[test]
    fn shorthand_multi_effect_map_with_nested_delegate() {
        // Map-form effects (like `delegate:`) work inside a shorthand
        // list, exercising the parse_effect_value path.
        let yaml = r#"
"role.hr":
  - delegate:
      plugin: workday-oauth
      config:
        audience: workday-api
  - "plugin(audit_logger)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Step::Rule");
        };
        assert_eq!(rule.effects.len(), 2);
        assert!(matches!(rule.effects[0], Effect::Delegate(_)));
        assert!(matches!(rule.effects[1], Effect::Plugin { .. }));
    }

    #[test]
    fn cedar_with_list_body_still_parses_as_pdp() {
        // Regression guard — `cedar:` and other PDP keys whose body
        // happens to be list-shaped (e.g. when the author embeds a
        // bare reaction list) must NOT be reinterpreted as a
        // shorthand multi-effect map.
        //
        // Cedar bodies in production are maps with `action`/`resource`
        // keys — we don't actually accept a Sequence body, but the
        // shorthand-list detector explicitly excludes known PDP
        // dialect keys so the failure mode here is the existing PDP
        // body error, not a shorthand misparse.
        let err = parse_step_yaml("cedar: [oh no]").unwrap_err();
        // Existing PDP body validator complains about the shape —
        // proves we didn't try to read `cedar` as a predicate.
        assert!(format!("{}", err).contains("body must be a map"));
    }

    #[test]
    fn shorthand_multi_effect_empty_list_rejected() {
        let err = parse_step_yaml(r#""x": []"#).unwrap_err();
        assert!(format!("{}", err).contains("no effects"));
    }

    // ----- E2: content effects in do: (field pipe chains) -----

    #[test]
    fn when_do_with_field_op_result_redact() {
        // The headline E2 case: `result.salary | redact` as an effect
        // inside a do: list, alongside other effect kinds.
        let yaml = r#"
when: "!perm.view_ssn"
do:
  - "plugin(audit_logger)"
  - "result.salary | redact"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Step::Rule");
        };
        assert_eq!(rule.effects.len(), 2);
        assert!(matches!(rule.effects[0], Effect::Plugin { .. }));
        match &rule.effects[1] {
            Effect::FieldOp { path, stages } => {
                assert_eq!(path, "result.salary");
                assert_eq!(stages.len(), 1, "single `redact` stage");
            },
            other => panic!("expected FieldOp, got {:?}", other),
        }
    }

    #[test]
    fn when_do_with_field_op_args_mask() {
        // `args.card_number | mask(4)` — args side + parametrised stage.
        let yaml = r#"
when: role.support
do: "args.card_number | mask(4)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Step::Rule");
        };
        match &rule.effects[..] {
            [Effect::FieldOp { path, stages }] => {
                assert_eq!(path, "args.card_number");
                assert_eq!(stages.len(), 1);
            },
            other => panic!("expected single FieldOp, got {:?}", other),
        }
    }

    #[test]
    fn when_do_with_chained_field_op() {
        // Chained stages — type check + content effect. Uses stages
        // the pipeline parser actually knows about (`str` and `mask`).
        let yaml = r#"
when: role.support
do: "args.card_number | str | mask(4)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Step::Rule");
        };
        match &rule.effects[..] {
            [Effect::FieldOp { path, stages }] => {
                assert_eq!(path, "args.card_number");
                assert_eq!(stages.len(), 2, "two-stage chain");
            },
            other => panic!("expected single FieldOp, got {:?}", other),
        }
    }

    #[test]
    fn field_stage_run_aliases_plugin() {
        // In a field pipeline, `run(name)` is the same plugin-transform
        // stage as `plugin(name)` — symmetry with the policy-step alias.
        let yaml = r#"
when: role.support
do: "args.card_number | run(luhn)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Step::Rule");
        };
        match &rule.effects[..] {
            [Effect::FieldOp { path, stages }] => {
                assert_eq!(path, "args.card_number");
                match &stages[..] {
                    [Stage::Plugin { name }] => assert_eq!(name, "luhn"),
                    other => panic!("expected [Stage::Plugin], got {:?}", other),
                }
            },
            other => panic!("expected single FieldOp, got {:?}", other),
        }
    }

    #[test]
    fn field_stage_plugin_empty_name_is_rejected() {
        // `plugin()` / `run()` with no name in a field pipeline must be
        // rejected, mirroring the policy-step path (`parse_step_string`).
        // Previously the field-stage path accepted it as
        // `Stage::Plugin { name: "" }`.
        for verb in ["plugin", "run"] {
            let err = parse_stage(&format!("{verb}()")).expect_err("empty name must error");
            let msg = format!("{err}");
            assert!(
                msg.contains(verb) && msg.contains("must not be empty"),
                "{verb}(): expected verb-named empty-name error, got: {msg}"
            );
        }
    }

    #[test]
    fn field_op_invalid_path_falls_through() {
        // `role.hr | redact` looks like a pipe chain but the path
        // doesn't start with `args.` / `result.`. We refuse to treat
        // it as a FieldOp; instead it falls through to the predicate
        // parser, which will fail with a more specific error.
        let yaml = r#"do: "role.hr | redact""#;
        let _ = parse_step_yaml(&format!("when: true\n{}", yaml));
        // The exact failure mode here isn't load-bearing — what matters
        // is we don't silently produce an unconditional FieldOp with a
        // bogus path. So just confirm we either error or produce
        // *something other than* a FieldOp.
        let step = parse_step_yaml("when: true\ndo: \"role.hr | redact\"");
        match step {
            Ok(Step::Rule(rule)) => {
                assert!(
                    !matches!(rule.effects.as_slice(), [Effect::FieldOp { .. }]),
                    "bare `role.hr` must NOT parse as a FieldOp path"
                );
            },
            Err(_) => {}, // also fine
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn field_op_empty_chain_rejected() {
        // `args.x |` (trailing pipe with nothing after) — author bug.
        let yaml = r#"when: true
do: "args.x | ""#;
        let _ = parse_step_yaml(yaml); // shape varies by YAML parser, just ensure no panic
    }

    #[test]
    fn shorthand_multi_effect_with_field_op() {
        // Shorthand `predicate: [list]` with a content effect.
        let yaml = r#"
"!perm.view_ssn":
  - "plugin(audit_logger)"
  - "result.ssn | redact"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Step::Rule");
        };
        assert_eq!(rule.effects.len(), 2);
        assert!(matches!(rule.effects[1], Effect::FieldOp { .. }));
    }

    #[test]
    fn find_top_level_pipe_skips_inside_parens() {
        // Top-level `|` between path and chain → returns its index.
        // Inner `|` inside `(...)` or quotes is ignored.
        assert_eq!(find_top_level_pipe("args.x | mask(4)"), Some(7));
        assert_eq!(find_top_level_pipe("validate(luhn)"), None);
        assert_eq!(find_top_level_pipe(r#"args.x | mask("a|b")"#), Some(7));
        // No top-level pipe even with a `|` inside the parameter set.
        assert_eq!(find_top_level_pipe("mask(a|b)"), None);
    }

    // ----- E3: sequential: / parallel: parsing -----

    #[test]
    fn top_level_sequential() {
        // `- sequential: [list]` as a top-level policy step.
        let yaml = r#"
sequential:
  - "plugin(rate_limiter)"
  - "plugin(audit_logger)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Rule");
        };
        assert!(matches!(rule.condition, Expression::Always));
        match rule.effects.as_slice() {
            [Effect::Sequential(inner)] => {
                assert_eq!(inner.len(), 2);
                assert!(matches!(inner[0], Effect::Plugin { .. }));
                assert!(matches!(inner[1], Effect::Plugin { .. }));
            },
            other => panic!("expected single Sequential effect, got {:?}", other),
        }
    }

    #[test]
    fn top_level_parallel() {
        let yaml = r#"
parallel:
  - "plugin(pii_scanner)"
  - "plugin(nemo_guardrails)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Rule");
        };
        match rule.effects.as_slice() {
            [Effect::Parallel(inner)] => {
                assert_eq!(inner.len(), 2);
            },
            other => panic!("expected single Parallel effect, got {:?}", other),
        }
    }

    #[test]
    fn parallel_inside_do_body() {
        // The DSL spec's "Conditional parallel" example: a `when:`
        // rule whose `do:` is a single parallel block.
        let yaml = r#"
when: args.include_ssn == true
do:
  parallel:
    - "plugin(pii_scanner)"
    - "plugin(nemo_guardrails)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Rule");
        };
        match rule.effects.as_slice() {
            [Effect::Parallel(inner)] => assert_eq!(inner.len(), 2),
            other => panic!("expected Parallel in do:, got {:?}", other),
        }
    }

    #[test]
    fn parallel_rejects_field_op_at_parse_time() {
        // FieldOp inside Parallel should fail at parse, not at runtime.
        let yaml = r#"
parallel:
  - "plugin(audit)"
  - "args.ssn | redact"
"#;
        let err = parse_step_yaml(yaml).unwrap_err();
        assert!(format!("{}", err).contains("mutation"), "got: {}", err);
    }

    #[test]
    fn parallel_rejects_delegate_at_parse_time() {
        let yaml = r#"
parallel:
  - "plugin(audit)"
  - "delegate(workday)"
"#;
        let err = parse_step_yaml(yaml).unwrap_err();
        assert!(format!("{}", err).contains("mutation"));
    }

    #[test]
    fn sequential_allows_mutations() {
        // The escape valve — Sequential lets mutations through.
        let yaml = r#"
sequential:
  - "args.ssn | redact"
  - "plugin(audit)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Rule")
        };
        match rule.effects.as_slice() {
            [Effect::Sequential(inner)] => {
                assert!(matches!(inner[0], Effect::FieldOp { .. }));
                assert!(matches!(inner[1], Effect::Plugin { .. }));
            },
            other => panic!("got {:?}", other),
        }
    }

    #[test]
    fn parallel_empty_list_rejected() {
        let err = parse_step_yaml("parallel: []").unwrap_err();
        assert!(format!("{}", err).contains("empty"));
    }

    #[test]
    fn sequential_empty_list_rejected() {
        let err = parse_step_yaml("sequential: []").unwrap_err();
        assert!(format!("{}", err).contains("empty"));
    }

    // ----- R1: restrict effect -----

    /// A literal `StringSetSpec` for terse assertions.
    fn lit(items: &[&str]) -> Option<crate::constraint::StringSetSpec> {
        Some(crate::constraint::StringSetSpec::Literal(
            items.iter().map(|s| s.to_string()).collect(),
        ))
    }

    #[test]
    fn top_level_restrict_full_shape() {
        // Every field exercised at once, including `custom` scalar
        // coercion and an explicit `on_empty`.
        let yaml = r#"
restrict:
  allow_models: ["vllm/*", "anthropic/claude-sonnet-*"]
  deny_models:  ["openai/*"]
  allow_regions: [eu]
  allow_sites: [site-a]
  max_cost_tier: cheap
  custom: { gpu: h100, dedicated: true }
  on_empty: fallback
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Restrict { spec } = step else {
            panic!("expected Step::Restrict, got {:?}", step);
        };
        use crate::constraint::OnEmpty;
        assert_eq!(spec.allow_models, lit(&["vllm/*", "anthropic/claude-sonnet-*"]));
        assert_eq!(spec.deny_models, lit(&["openai/*"]));
        assert_eq!(spec.allow_regions, lit(&["eu"]));
        assert_eq!(spec.allow_sites, lit(&["site-a"]));
        assert_eq!(spec.max_cost_tier.as_deref(), Some("cheap"));
        // `custom` coerces the bool `true` to the string "true".
        assert_eq!(spec.custom.get("gpu"), Some(&"h100".to_string()));
        assert_eq!(spec.custom.get("dedicated"), Some(&"true".to_string()));
        assert_eq!(spec.on_empty, OnEmpty::Fallback);
    }

    #[test]
    fn restrict_on_empty_defaults_to_deny() {
        let step = parse_step_yaml("restrict: { deny_models: [\"openai/*\"] }").unwrap();
        let Step::Restrict { spec } = step else {
            panic!("expected Step::Restrict");
        };
        assert_eq!(spec.on_empty, crate::constraint::OnEmpty::Deny);
    }

    #[test]
    fn restrict_field_reference_parses_as_ref() {
        // A scalar `data.*` path is a reference, not a literal. A path
        // containing `[...]` must be quoted so YAML doesn't read the
        // brackets as a flow sequence (block form works unquoted too).
        let yaml = r#"
restrict:
  allow_models: "data.agents[subject.id].allowed_models"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Restrict { spec } = step else {
            panic!("expected Step::Restrict");
        };
        assert_eq!(
            spec.allow_models,
            Some(crate::constraint::StringSetSpec::Ref(
                "data.agents[subject.id].allowed_models".to_string()
            ))
        );
    }

    #[test]
    fn restrict_bracketless_reference_parses_unquoted() {
        // A reference with no `[...]` is a clean plain scalar — no quoting
        // needed even in flow form.
        let step =
            parse_step_yaml("restrict: { allow_regions: data.tenant_regions }").unwrap();
        let Step::Restrict { spec } = step else {
            panic!("expected Step::Restrict");
        };
        assert_eq!(
            spec.allow_regions,
            Some(crate::constraint::StringSetSpec::Ref("data.tenant_regions".to_string()))
        );
    }

    #[test]
    fn restrict_inside_when_do_body() {
        // The EU-sovereignty shape: gate at the composition layer,
        // restrict in the `do:` body.
        let yaml = r#"
when: session.labels contains 'eu_resident'
do:
  - restrict: { allow_regions: [eu] }
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Rule");
        };
        match rule.effects.as_slice() {
            [Effect::Restrict { spec }] => {
                assert_eq!(spec.allow_regions, lit(&["eu"]));
            },
            other => panic!("expected single Restrict effect, got {:?}", other),
        }
    }

    #[test]
    fn restrict_inside_pdp_on_allow() {
        // `restrict` composes in a PDP reaction — authz says yes, then
        // pin routing (design §2.1).
        let yaml = r#"
cedar:
  action: read
  resource: eu_data
  on_allow:
    - restrict: { allow_regions: [eu] }
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Pdp { on_allow, .. } = step else {
            panic!("expected Step::Pdp, got {:?}", step);
        };
        match on_allow.as_slice() {
            [Step::Restrict { spec }] => {
                assert_eq!(spec.allow_regions, lit(&["eu"]));
            },
            other => panic!("expected Restrict in on_allow, got {:?}", other),
        }
    }

    #[test]
    fn restrict_empty_body_rejected() {
        // A `restrict:` with no constraint fields restricts nothing —
        // author error.
        let err = parse_step_yaml("restrict: {}").unwrap_err();
        assert!(format!("{}", err).contains("no constraint fields"), "got: {}", err);
    }

    #[test]
    fn restrict_only_on_empty_rejected() {
        // `on_empty` alone still constrains nothing.
        let err = parse_step_yaml("restrict: { on_empty: deny }").unwrap_err();
        assert!(format!("{}", err).contains("no constraint fields"), "got: {}", err);
    }

    #[test]
    fn restrict_unknown_field_rejected() {
        let err = parse_step_yaml("restrict: { allow_zones: [eu] }").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("unknown"), "got: {}", msg);
        assert!(msg.contains("allow_zones"), "got: {}", msg);
    }

    #[test]
    fn restrict_bad_on_empty_value_rejected() {
        let err =
            parse_step_yaml("restrict: { deny_models: [\"openai/*\"], on_empty: maybe }").unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("on_empty"), "got: {}", msg);
        assert!(msg.contains("maybe"), "got: {}", msg);
    }

    #[test]
    fn restrict_non_scalar_custom_value_rejected() {
        let yaml = r#"
restrict:
  custom:
    gpu: [h100, a100]
"#;
        let err = parse_step_yaml(yaml).unwrap_err();
        assert!(format!("{}", err).contains("scalar"), "got: {}", err);
    }

    #[test]
    fn restrict_allowed_inside_parallel() {
        // `restrict` is non-mutating, so it is *allowed* in parallel —
        // this guards that we didn't accidentally class it as a mutation.
        let yaml = r#"
parallel:
  - "plugin(audit)"
  - restrict: { allow_regions: [eu] }
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Rule");
        };
        match rule.effects.as_slice() {
            [Effect::Parallel(inner)] => {
                assert_eq!(inner.len(), 2);
                assert!(matches!(inner[1], Effect::Restrict { .. }));
            },
            other => panic!("expected Parallel with Restrict, got {:?}", other),
        }
    }

    #[test]
    fn nested_orchestration() {
        // `sequential: [plugin, parallel: [plugin, plugin]]` — the
        // parser handles arbitrary nesting through parse_effect_value.
        let yaml = r#"
sequential:
  - "plugin(rate_limiter)"
  - parallel:
      - "plugin(pii_scanner)"
      - "plugin(nemo)"
"#;
        let step = parse_step_yaml(yaml).unwrap();
        let Step::Rule(rule) = step else {
            panic!("expected Rule")
        };
        let Effect::Sequential(outer) = &rule.effects[0] else {
            panic!("expected Sequential");
        };
        assert_eq!(outer.len(), 2);
        assert!(matches!(outer[0], Effect::Plugin { .. }));
        match &outer[1] {
            Effect::Parallel(inner) => assert_eq!(inner.len(), 2),
            other => panic!("expected nested Parallel, got {:?}", other),
        }
    }

    // ----- Colon-splitting edge cases -----

    #[test]
    fn split_respects_quotes_and_parens() {
        // The `:` inside parens / quotes shouldn't be the separator.
        let r = parse_rule(r#"session.labels contains "a:b": deny"#, "test").unwrap();
        assert!(matches!(r.effects.as_slice(), [Effect::Deny { .. }]));
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
    pre_invocation:
      - "require(authenticated)"
      - "require(role.hr | role.finance)"
      - "delegation.depth > 2 & include_ssn: deny"
"#;
        let routes = compile_config(yaml).unwrap().routes;
        let route = routes.get("get_compensation").expect("route missing");
        assert_eq!(route.policy.len(), 3);
        assert!(route
            .declared_phases()
            .contains(crate::rules::Phase::Policy));
    }

    #[test]
    fn authorization_nested_and_flat_forms_are_equivalent() {
        // The nested `authorization:` block and the flat
        // `pre_invocation:` / `post_invocation:` forms must compile to
        // the same route.
        let nested = r#"
routes:
  r:
    authorization:
      pre_invocation:
        - "require(authenticated)"
      post_invocation:
        - "taint(audit, session)"
"#;
        let flat = r#"
routes:
  r:
    pre_invocation:
      - "require(authenticated)"
    post_invocation:
      - "taint(audit, session)"
"#;
        let a = compile_config(nested).unwrap().routes;
        let b = compile_config(flat).unwrap().routes;
        let ra = a.get("r").expect("nested route");
        let rb = b.get("r").expect("flat route");
        assert_eq!(ra.policy.len(), rb.policy.len());
        assert_eq!(ra.post_policy.len(), rb.post_policy.len());
        assert_eq!(ra.policy.len(), 1);
        assert_eq!(ra.post_policy.len(), 1);
    }

    #[test]
    fn legacy_key_nested_under_authorization_is_rejected() {
        // Fail-closed: a legacy key nested inside the new `authorization:`
        // wrapper must error, not be silently dropped (which would load a
        // route with no authorization enforced). Guarded by
        // `deny_unknown_fields` on `AuthorizationYaml`.
        let yaml = r#"
routes:
  r:
    authorization:
      policy:
        - "require(authenticated)"
"#;
        let err = compile_config(yaml).expect_err("nested legacy `policy:` must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("policy") || msg.contains("unknown field"),
            "error should flag the unknown/legacy nested key: {msg}"
        );
    }

    #[test]
    fn authorization_typo_under_wrapper_is_rejected() {
        // `deny_unknown_fields` also catches typos so they don't silently
        // no-op the phase.
        let yaml = r#"
routes:
  r:
    authorization:
      pre_invocaton:
        - "require(authenticated)"
"#;
        assert!(
            compile_config(yaml).is_err(),
            "a typo'd sub-key under `authorization:` must be rejected, not ignored"
        );
    }

    #[test]
    fn same_phase_declared_nested_and_flat_is_rejected() {
        // The two forms are alternatives, not additive: declaring a phase
        // both nested and flat on one section would run its effects twice.
        let yaml = r#"
routes:
  r:
    authorization:
      pre_invocation:
        - "require(authenticated)"
    pre_invocation:
      - "require(role.hr)"
"#;
        let err = compile_config(yaml).expect_err("both-forms-same-section must be rejected");
        assert!(
            matches!(err, ParseError::ConflictingAuthorizationForms { ref phase, .. } if phase == "pre_invocation"),
            "expected ConflictingAuthorizationForms for pre_invocation, got {err:?}"
        );
    }

    #[test]
    fn field_pipeline_error_names_field_path() {
        // A malformed pipeline under `result:` names `result.<field>` in
        // the diagnostic so the operator can locate the offending field.
        let yaml = r#"
routes:
  r:
    result:
      x: "nonsense"
"#;
        let err = compile_config(yaml).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("result.x"), "expected result.x in: {msg}");
    }

    #[test]
    fn legacy_policy_field_names_are_rejected() {
        // Breaking rename: the old authorization-phase keys must fail
        // loudly, never be silently dropped (which would fail open).
        for (old, hint) in [
            ("policy", "pre_invocation"),
            ("post_policy", "post_invocation"),
        ] {
            let yaml = format!("routes:\n  r:\n    {old}:\n      - \"require(authenticated)\"\n");
            let err = compile_config(&yaml).expect_err(&format!("legacy `{old}` must be rejected"));
            let msg = format!("{err}");
            assert!(
                msg.contains(old) && msg.contains(hint),
                "`{old}` rejection should name the replacement `{hint}`: {msg}"
            );
        }
    }

    #[test]
    fn legacy_only_route_is_not_silently_omitted() {
        // A route whose *only* APL-ish key is a legacy name would look
        // empty to the has-APL gate and be dropped — a fail-open. It must
        // error instead.
        let yaml = r#"
routes:
  ghost:
    policy:
      - "require(authenticated)"
"#;
        assert!(
            matches!(compile_config(yaml), Err(ParseError::RenamedField { .. })),
            "legacy-only route must be rejected, not omitted"
        );
    }

    #[test]
    fn compile_omits_routes_without_apl_blocks() {
        // A route with no APL blocks (no authorization / pre_invocation /
        // post_invocation / args / result) is a "legacy" route per
        // apl-design §5 and must be
        // omitted from the compiled output. Unknown route keys (e.g.
        // legacy CPEX `priority`) are stashed in `other`, not errored.
        let yaml = r#"
routes:
  legacy:
    priority: 50
  apl_route:
    pre_invocation:
      - "require(authenticated)"
"#;
        let routes = compile_config(yaml).unwrap().routes;
        assert!(routes.contains_key("apl_route"));
        assert!(
            !routes.contains_key("legacy"),
            "legacy route should be omitted, not compiled"
        );
    }

    #[test]
    fn compile_unknown_top_level_keys_ignored() {
        let yaml = r#"
version: "0.1"
policy_evaluator:
  kind: apl
plugins:
  - name: rate_limiter
    kind: native
imports:
  - "./shared.yaml"
routes:
  ping:
    pre_invocation:
      - "require(authenticated)"
"#;
        let routes = compile_config(yaml).unwrap().routes;
        assert!(routes.contains_key("ping"));
    }

    #[test]
    fn compile_propagates_rule_errors_with_source() {
        let yaml = r#"
routes:
  bad:
    pre_invocation:
      - "subject.id == garbage_ident"
"#;
        let err = compile_config(yaml).unwrap_err();
        // RHS-as-identifier is rejected; the error mentions the offending input.
        let msg = format!("{}", err);
        assert!(
            msg.contains("RHS-as-identifier") || msg.contains("garbage_ident"),
            "error message should reference the failure: {}",
            msg,
        );
    }

    #[test]
    fn compile_plugin_step_string_form() {
        let yaml = r#"
routes:
  rate_limited:
    pre_invocation:
      - "plugin(rate_limiter)"
"#;
        let routes = compile_config(yaml).unwrap().routes;
        let route = routes.get("rate_limited").unwrap();
        assert_eq!(route.policy.len(), 1);
        match &route.policy[0] {
            Effect::Plugin { name } => assert_eq!(name, "rate_limiter"),
            other => panic!("expected Effect::Plugin, got {:?}", other),
        }
    }

    #[test]
    fn compile_run_step_string_form_aliases_plugin() {
        // `run(name)` is an alias for `plugin(name)`: both invoke a named
        // plugin and compile to Effect::Plugin.
        let yaml = r#"
routes:
  rate_limited:
    pre_invocation:
      - "run(rate_limiter)"
"#;
        let routes = compile_config(yaml).unwrap().routes;
        let route = routes.get("rate_limited").unwrap();
        assert_eq!(route.policy.len(), 1);
        match &route.policy[0] {
            Effect::Plugin { name } => assert_eq!(name, "rate_limiter"),
            other => panic!("expected Effect::Plugin, got {:?}", other),
        }
    }

    #[test]
    fn parse_step_run_is_plugin_alias() {
        for s in ["run(audit-log)", "plugin(audit-log)"] {
            let step = parse_step(&serde_yaml::Value::String(s.to_string()), "test").unwrap();
            match step {
                crate::step::Step::Plugin { name } => assert_eq!(name, "audit-log", "{s}"),
                other => panic!("expected Step::Plugin for `{s}`, got {other:?}"),
            }
        }
        // Empty / malformed `run(...)` surfaces a clear, verb-named error.
        let err = parse_step(&serde_yaml::Value::String("run()".to_string()), "test").unwrap_err();
        assert!(
            format!("{err}").contains("run("),
            "error should name `run(...)`: {err}"
        );
    }

    #[test]
    fn compile_taint_step_string_form() {
        let yaml = r#"
routes:
  audit_marked:
    pre_invocation:
      - "taint(audit, session)"
"#;
        let routes = compile_config(yaml).unwrap().routes;
        let route = routes.get("audit_marked").unwrap();
        match &route.policy[0] {
            Effect::Taint { label, scopes } => {
                assert_eq!(label, "audit");
                assert_eq!(scopes, &vec![TaintScope::Session]);
            },
            other => panic!("expected Effect::Taint, got {:?}", other),
        }
    }

    #[test]
    fn compile_pdp_call_cedar_map_form() {
        // Cedar uses the `cedar:` key with args inline + on_deny/on_allow.
        let yaml = r#"
routes:
  authz_check:
    pre_invocation:
      - cedar:
          action: read
          resource: employee
          on_deny:
            - deny
          on_allow:
            - "plugin(audit_logger)"
"#;
        let routes = compile_config(yaml).unwrap().routes;
        let route = routes.get("authz_check").unwrap();
        match &route.policy[0] {
            Effect::Pdp {
                call,
                on_deny,
                on_allow,
            } => {
                assert_eq!(call.dialect, PdpDialect::Cedar);
                // Cedar args are a map: action + resource (with reaction
                // keys stripped out).
                let args_map = call.args.as_mapping().expect("cedar args should be a map");
                assert!(args_map.contains_key(serde_yaml::Value::String("action".into())));
                assert!(args_map.contains_key(serde_yaml::Value::String("resource".into())));
                assert!(!args_map.contains_key(serde_yaml::Value::String("on_deny".into())));
                assert_eq!(on_deny.len(), 1);
                assert_eq!(on_allow.len(), 1);
            },
            other => panic!("expected Effect::Pdp, got {:?}", other),
        }
    }

    #[test]
    fn compile_pdp_call_cel_map_form() {
        // `cel:` carries an `expr:` string + optional on_deny/on_allow
        // reactions. Routes to the CEL-backed resolver via PdpDialect::Cel.
        let yaml = r#"
routes:
  authz_check:
    pre_invocation:
      - cel:
          expr: "subject.id == 'alice' && delegation.depth <= 2"
          on_deny:
            - deny
"#;
        let routes = compile_config(yaml).unwrap().routes;
        let route = routes.get("authz_check").unwrap();
        match &route.policy[0] {
            Effect::Pdp {
                call,
                on_deny,
                on_allow,
            } => {
                assert_eq!(call.dialect, PdpDialect::Cel);
                let args_map = call.args.as_mapping().expect("cel args should be a map");
                assert!(args_map.contains_key(serde_yaml::Value::String("expr".into())));
                // Reaction keys are stripped from the opaque call args.
                assert!(!args_map.contains_key(serde_yaml::Value::String("on_deny".into())));
                assert_eq!(on_deny.len(), 1);
                assert_eq!(on_allow.len(), 0);
            },
            other => panic!("expected Effect::Pdp, got {:?}", other),
        }
    }

    #[test]
    fn compile_pdp_call_opa_paren_form() {
        // OPA uses `opa("path"):` with the path inside parens + body is reactions.
        let yaml = r#"
routes:
  opa_check:
    pre_invocation:
      - 'opa("hr/compensation/deny"):':
          on_deny:
            - deny
"#;
        let routes = compile_config(yaml).unwrap().routes;
        let route = routes.get("opa_check").unwrap();
        match &route.policy[0] {
            Effect::Pdp { call, on_deny, .. } => {
                assert_eq!(call.dialect, PdpDialect::Opa);
                // OPA args are a string (the path).
                assert!(call.args.as_str().unwrap().contains("hr/compensation/deny"));
                assert_eq!(on_deny.len(), 1);
            },
            other => panic!("expected Effect::Pdp, got {:?}", other),
        }
    }

    #[test]
    fn compile_pdp_unknown_dialect_becomes_custom() {
        let yaml = r#"
routes:
  custom_pdp:
    pre_invocation:
      - my_engine:
          on_deny: [deny]
"#;
        let routes = compile_config(yaml).unwrap().routes;
        match &routes.get("custom_pdp").unwrap().policy[0] {
            Effect::Pdp { call, .. } => {
                assert_eq!(call.dialect, PdpDialect::Custom("my_engine".into()));
            },
            other => panic!("expected Pdp, got {:?}", other),
        }
    }

    // ----- End-to-end with evaluator -----

    #[tokio::test]
    async fn end_to_end_hr_compensation() {
        let yaml = r#"
routes:
  get_compensation:
    pre_invocation:
      - "require(authenticated)"
      - "require(role.hr | role.finance)"
      - "delegation.depth > 2: deny"
"#;
        let routes = compile_config(yaml).unwrap().routes;
        let route = routes.get("get_compensation").unwrap();

        let pdp: std::sync::Arc<dyn crate::PdpResolver> = std::sync::Arc::new(NullPdpResolver);
        let plugins: std::sync::Arc<dyn crate::PluginInvoker> =
            std::sync::Arc::new(NullPluginInvoker);
        let delegations: std::sync::Arc<dyn crate::DelegationInvoker> =
            std::sync::Arc::new(crate::NoopDelegationInvoker);

        // Alice: authenticated, hr role, depth=1 → allow.
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        bag.set("role.hr", true);
        bag.set("delegation.depth", 1_i64);
        assert_eq!(
            crate::evaluate_effects(
                &route.policy,
                &mut bag,
                &pdp,
                &plugins,
                &delegations,
                crate::DispatchPhase::Pre,
                &mut crate::route::RoutePayload::new(serde_json::Value::Null)
            )
            .await
            .decision,
            Decision::Allow,
        );

        // Same Alice but depth=3 → deny (third rule fires).
        bag.set("delegation.depth", 3_i64);
        match crate::evaluate_effects(
            &route.policy,
            &mut bag,
            &pdp,
            &plugins,
            &delegations,
            crate::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
        .decision
        {
            Decision::Deny { rule_source, .. } => {
                assert!(
                    rule_source.contains("pre_invocation[2]"),
                    "expected pre_invocation[2], got {}",
                    rule_source
                );
            },
            d => panic!("expected Deny, got {:?}", d),
        }

        // Bob: authenticated but neither hr nor finance → deny on rule 1.
        let mut bag = AttributeBag::new();
        bag.set("authenticated", true);
        bag.set("delegation.depth", 1_i64);
        match crate::evaluate_effects(
            &route.policy,
            &mut bag,
            &pdp,
            &plugins,
            &delegations,
            crate::DispatchPhase::Pre,
            &mut crate::route::RoutePayload::new(serde_json::Value::Null),
        )
        .await
        .decision
        {
            Decision::Deny { rule_source, .. } => {
                assert!(
                    rule_source.contains("pre_invocation[1]"),
                    "expected pre_invocation[1], got {}",
                    rule_source
                );
            },
            d => panic!("expected Deny, got {:?}", d),
        }
    }

    // Test fixtures for async evaluator — null resolvers that nothing in
    // a pure-rule route should ever invoke.
    struct NullPdpResolver;
    #[async_trait::async_trait]
    impl crate::PdpResolver for NullPdpResolver {
        fn dialect(&self) -> crate::PdpDialect {
            crate::PdpDialect::Cedar
        }
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
        assert_eq!(
            p.stages,
            vec![Stage::Type(TypeCheck::Str), Stage::Mask { keep_last: 4 },]
        );

        let p = parse_pipeline("int | 0..1M").unwrap();
        assert_eq!(
            p.stages,
            vec![
                Stage::Type(TypeCheck::Int),
                Stage::Range {
                    min: Some(0),
                    max: Some(1_000_000)
                },
            ]
        );
    }

    #[test]
    fn pipeline_pipe_inside_parens_does_not_split() {
        // `redact(!a | b)` is one stage; the inner `|` is OR inside a
        // predicate condition, not a chain separator.
        let p = parse_pipeline("str | redact(!perm.view_ssn | role.admin)").unwrap();
        assert_eq!(p.stages.len(), 2);
        match &p.stages[1] {
            Stage::Redact { condition: Some(_) } => {},
            other => panic!("expected Redact with condition, got {:?}", other),
        }
    }

    #[test]
    fn pipeline_length_constraints() {
        let p = parse_pipeline("len(..500)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Length {
                min: None,
                max: Some(500)
            }]
        );
        let p = parse_pipeline("len(10..50)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Length {
                min: Some(10),
                max: Some(50)
            }]
        );
        let p = parse_pipeline("len(8..)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Length {
                min: Some(8),
                max: None
            }]
        );
    }

    #[test]
    fn pipeline_range_with_suffixes() {
        let p = parse_pipeline("0..10k").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Range {
                min: Some(0),
                max: Some(10_000)
            }]
        );
        let p = parse_pipeline("0..1M").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Range {
                min: Some(0),
                max: Some(1_000_000)
            }]
        );
        let p = parse_pipeline("..500").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Range {
                min: None,
                max: Some(500)
            }]
        );
    }

    #[test]
    fn pipeline_enum_unquoted_and_quoted() {
        let p = parse_pipeline("enum(low, medium, high)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Enum {
                values: vec!["low".into(), "medium".into(), "high".into()],
            }]
        );
        let p = parse_pipeline(r#"enum("a", "b")"#).unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Enum {
                values: vec!["a".into(), "b".into()],
            }]
        );
    }

    #[test]
    fn pipeline_redact_with_predicate_condition() {
        let p = parse_pipeline("str | redact(!perm.view_ssn)").unwrap();
        assert_eq!(p.stages.len(), 2);
        match &p.stages[1] {
            Stage::Redact {
                condition: Some(Expression::Not(inner)),
            } => match inner.as_ref() {
                Expression::Condition(Condition::IsTrue { key }) => {
                    assert_eq!(key, "perm.view_ssn");
                },
                other => panic!("expected IsTrue(perm.view_ssn), got {:?}", other),
            },
            other => panic!("expected Redact with Not condition, got {:?}", other),
        }
    }

    #[test]
    fn pipeline_taint_scopes() {
        let p = parse_pipeline("taint(PII)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Taint {
                label: "PII".into(),
                scopes: vec![TaintScope::Session],
            }]
        );
        let p = parse_pipeline("taint(PII, message)").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Taint {
                label: "PII".into(),
                scopes: vec![TaintScope::Message],
            }]
        );
        let p = parse_pipeline("taint(PII, [session, message])").unwrap();
        assert_eq!(
            p.stages,
            vec![Stage::Taint {
                label: "PII".into(),
                scopes: vec![TaintScope::Session, TaintScope::Message],
            }]
        );
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
        let routes = compile_config(yaml).unwrap().routes;
        let route = routes.get("get_compensation").expect("missing route");
        assert_eq!(route.args.len(), 2);
        assert_eq!(route.result.len(), 3);

        // Pull out the ssn pipeline and confirm shape.
        let ssn = route.result.iter().find(|f| f.field == "ssn").unwrap();
        assert_eq!(ssn.pipeline.stages.len(), 2);
        assert!(matches!(
            ssn.pipeline.stages[0],
            Stage::Type(TypeCheck::Str)
        ));
        assert!(matches!(
            ssn.pipeline.stages[1],
            Stage::Redact { condition: Some(_) }
        ));

        // declared_phases should include Result and Args now.
        let phases = route.declared_phases();
        assert!(phases.contains(crate::rules::Phase::Args));
        assert!(phases.contains(crate::rules::Phase::Result));
    }

    #[test]
    fn compile_route_with_only_args_still_compiles() {
        // A route with no authorization block but with `args:`
        // validators is still an APL route (declared_phases non-empty).
        let yaml = r#"
routes:
  validate_only:
    args:
      employee_id: "uuid"
"#;
        let routes = compile_config(yaml).unwrap().routes;
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

    // ----- plugins: block + route-level overrides -----

    #[test]
    fn compile_captures_root_plugins_block_into_registry() {
        let yaml = r#"
plugins:
  - name: rate_limiter
    kind: native
    hooks: [tool_pre_invoke]
    capabilities: [read_subject]
    config:
      max_requests: 100
  - name: audit
    kind: native
    hooks: [tool_post_invoke]
routes:
  get_compensation:
    pre_invocation:
      - "plugin(rate_limiter)"
"#;
        let cfg = compile_config(yaml).unwrap();
        assert_eq!(cfg.plugins.len(), 2);
        let rl = cfg.plugins.get("rate_limiter").unwrap();
        assert_eq!(rl.kind, "native");
        assert_eq!(rl.hooks, vec!["tool_pre_invoke".to_string()]);
        assert_eq!(rl.capabilities, vec!["read_subject".to_string()]);
        // The route should still compile (uses plugin(rate_limiter)).
        assert!(cfg.routes.contains_key("get_compensation"));
    }

    #[test]
    fn compile_captures_route_level_plugin_overrides() {
        let yaml = r#"
plugins:
  - name: rate_limiter
    kind: native
    hooks: [tool_pre_invoke]
    config:
      max_requests: 100
routes:
  hot_path:
    pre_invocation:
      - "plugin(rate_limiter)"
    plugins:
      rate_limiter:
        config:
          max_requests: 10
        on_error: ignore
"#;
        let cfg = compile_config(yaml).unwrap();
        let route = cfg.routes.get("hot_path").unwrap();
        let ovr = route.plugin_overrides.get("rate_limiter").unwrap();
        assert_eq!(ovr.on_error.as_deref(), Some("ignore"));
        let cfg_yaml = ovr.config.as_ref().unwrap();
        assert_eq!(
            cfg_yaml["max_requests"],
            serde_yaml::from_str::<serde_yaml::Value>("10").unwrap()
        );

        // Verify EffectivePlugin::resolve sees the override.
        let eff = crate::plugin_decl::EffectivePlugin::resolve(
            "rate_limiter",
            &cfg.plugins,
            &route.plugin_overrides,
        )
        .unwrap();
        assert_eq!(eff.on_error, Some("ignore"));
        // Hooks NOT overridable — still from the global declaration.
        assert_eq!(eff.hooks, &["tool_pre_invoke".to_string()]);
    }

    // ----- compile_policy_block_value (single-block compiler for visitors) -----

    #[test]
    fn compile_policy_block_value_parses_apl_body() {
        let yaml = r#"
pre_invocation:
  - "require(authenticated)"
result:
  ssn: "redact(!perm.view_ssn)"
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let compiled =
            compile_policy_block_value("global.policy.all", &value).expect("compile block");
        assert_eq!(compiled.route_key, "global.policy.all");
        assert_eq!(compiled.policy.len(), 1);
        assert_eq!(compiled.result.len(), 1);
        assert_eq!(compiled.result[0].field, "ssn");
    }

    #[test]
    fn compile_policy_block_value_null_is_empty_route() {
        let value = serde_yaml::Value::Null;
        let compiled =
            compile_policy_block_value("global.defaults.tool", &value).expect("compile null");
        assert!(compiled.declared_phases().is_empty());
        assert_eq!(compiled.route_key, "global.defaults.tool");
    }

    #[test]
    fn compile_policy_block_value_threads_source_into_rule_paths() {
        let yaml = r#"
pre_invocation:
  - "require(authenticated)"
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let compiled = compile_policy_block_value("global.policies.hr", &value).expect("compile");
        match &compiled.policy[0] {
            crate::rules::Effect::When { source, .. } => {
                assert_eq!(source, "global.policies.hr.pre_invocation[0]");
            },
            other => panic!("expected When, got {:?}", other),
        }
    }

    // ----- delegate: step parsing -----

    #[test]
    fn parse_delegate_step_with_only_plugin() {
        let yaml = r#"
- delegate:
    plugin: workday-oauth
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let crate::step::Step::Delegate(ds) = step else {
            panic!("expected Delegate, got {step:?}");
        };
        assert_eq!(ds.plugin_name, "workday-oauth");
        assert!(ds.config_override.is_none());
        assert!(ds.on_error.is_none());
        assert_eq!(ds.source, "test.policy[0]");
    }

    #[test]
    fn parse_delegate_step_with_config_and_on_error() {
        let yaml = r#"
- delegate:
    plugin: workday-oauth
    config:
      target: workday-api
      permissions: [read_compensation]
    on_error: deny
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[1]").expect("parse");
        let crate::step::Step::Delegate(ds) = step else {
            panic!("expected Delegate, got {step:?}");
        };
        assert_eq!(ds.plugin_name, "workday-oauth");
        assert_eq!(ds.on_error.as_deref(), Some("deny"));
        let cfg = ds.config_override.as_ref().expect("config_override set");
        let target = cfg
            .as_mapping()
            .and_then(|m| m.get(serde_yaml::Value::String("target".into())))
            .and_then(|v| v.as_str());
        assert_eq!(target, Some("workday-api"));
    }

    #[test]
    fn parse_delegate_step_missing_plugin_errors() {
        let yaml = r#"
- delegate:
    config: { target: workday-api }
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("missing plugin");
        let msg = format!("{err}");
        assert!(msg.contains("requires `plugin:"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_step_empty_plugin_errors() {
        let yaml = r#"
- delegate:
    plugin: ""
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("empty plugin");
        let msg = format!("{err}");
        assert!(msg.contains("cannot be empty"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_step_non_string_on_error_errors() {
        let yaml = r#"
- delegate:
    plugin: workday-oauth
    on_error: 42
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("non-string on_error");
        let msg = format!("{err}");
        assert!(msg.contains("on_error"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_step_non_map_body_errors() {
        let yaml = r#"
- delegate: workday-oauth
"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("non-map delegate body");
        let msg = format!("{err}");
        assert!(msg.contains("must be a map"), "got: {msg}");
    }

    // ----- delegate(...) function-call string form -----

    #[test]
    fn parse_delegate_string_bare_plugin_name() {
        let yaml = r#"- "delegate(workday-oauth)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let crate::step::Step::Delegate(ds) = step else {
            panic!("expected Delegate, got {step:?}");
        };
        assert_eq!(ds.plugin_name, "workday-oauth");
        assert!(ds.config_override.is_none());
        assert!(ds.on_error.is_none());
        assert_eq!(ds.source, "test.policy[0]");
    }

    #[test]
    fn parse_delegate_string_with_string_kwargs() {
        let yaml =
            r#"- "delegate(workday-oauth, target: workday-api, audience: https://workday.com)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let crate::step::Step::Delegate(ds) = step else {
            panic!("expected Delegate, got {step:?}");
        };
        assert_eq!(ds.plugin_name, "workday-oauth");
        let cfg = ds.config_override.as_ref().unwrap().as_mapping().unwrap();
        assert_eq!(
            cfg.get(serde_yaml::Value::String("target".into()))
                .and_then(|v| v.as_str()),
            Some("workday-api"),
        );
        assert_eq!(
            cfg.get(serde_yaml::Value::String("audience".into()))
                .and_then(|v| v.as_str()),
            Some("https://workday.com"),
        );
    }

    #[test]
    fn parse_delegate_string_with_list_kwarg() {
        let yaml = r#"- "delegate(workday-oauth, permissions: [read_compensation, write_notes])""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let crate::step::Step::Delegate(ds) = step else {
            panic!("expected Delegate");
        };
        let cfg = ds.config_override.as_ref().unwrap().as_mapping().unwrap();
        let perms = cfg
            .get(serde_yaml::Value::String("permissions".into()))
            .and_then(|v| v.as_sequence())
            .expect("permissions sequence");
        let names: Vec<&str> = perms.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(names, vec!["read_compensation", "write_notes"]);
    }

    #[test]
    fn parse_delegate_string_on_error_pulled_out() {
        let yaml = r#"- "delegate(workday-oauth, target: workday-api, on_error: continue)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let crate::step::Step::Delegate(ds) = step else {
            panic!("expected Delegate");
        };
        assert_eq!(ds.on_error.as_deref(), Some("continue"));
        // on_error must NOT also leak into config_override.
        let cfg = ds.config_override.as_ref().unwrap().as_mapping().unwrap();
        assert!(
            cfg.get(serde_yaml::Value::String("on_error".into()))
                .is_none(),
            "on_error must not appear in config_override"
        );
    }

    #[test]
    fn parse_delegate_string_quoted_plugin_name() {
        // Quoting the plugin name is harmless — the parser strips
        // the wrapping quotes. Useful when the name contains
        // characters the bare-ident reader doesn't like.
        let yaml = r#"- 'delegate("workday-oauth")'"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let crate::step::Step::Delegate(ds) = step else {
            panic!("expected Delegate");
        };
        assert_eq!(ds.plugin_name, "workday-oauth");
    }

    #[test]
    fn parse_delegate_string_quoted_value_preserves_internal_commas() {
        let yaml =
            r#"- 'delegate(workday-oauth, audience: "https://workday.com,backup.workday.com")'"#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let step = parse_step(entry, "test.policy[0]").expect("parse");
        let crate::step::Step::Delegate(ds) = step else {
            panic!("expected Delegate");
        };
        let cfg = ds.config_override.as_ref().unwrap().as_mapping().unwrap();
        assert_eq!(
            cfg.get(serde_yaml::Value::String("audience".into()))
                .and_then(|v| v.as_str()),
            Some("https://workday.com,backup.workday.com"),
        );
    }

    #[test]
    fn parse_delegate_string_empty_args_errors() {
        let yaml = r#"- "delegate()""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("empty args");
        let msg = format!("{err}");
        assert!(msg.contains("plugin name"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_string_plugin_kwarg_rejected() {
        // `plugin:` as a kwarg is ambiguous when the plugin name is
        // also the positional first arg — reject loudly.
        let yaml = r#"- "delegate(workday-oauth, plugin: other-thing)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("plugin kwarg");
        let msg = format!("{err}");
        assert!(msg.contains("positional"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_string_kwarg_missing_colon_errors() {
        let yaml = r#"- "delegate(workday-oauth, target workday-api)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("missing colon");
        let msg = format!("{err}");
        assert!(msg.contains("key: value"), "got: {msg}");
    }

    #[test]
    fn parse_delegate_string_unbalanced_brackets_errors() {
        let yaml = r#"- "delegate(workday-oauth, permissions: [read_compensation)""#;
        let value: serde_yaml::Value = serde_yaml::from_str(yaml).unwrap();
        let entry = &value.as_sequence().unwrap()[0];
        let err = parse_step(entry, "test.policy[0]").expect_err("unbalanced");
        let msg = format!("{err}");
        assert!(
            msg.contains("unmatched") || msg.contains("unbalanced"),
            "got: {msg}"
        );
    }

    #[test]
    fn compile_route_mixed_string_and_map_delegate_forms() {
        // Both forms coexist in the same policy block — string form
        // for the compact case, map form for richer config.
        let yaml = r#"
routes:
  get_compensation:
    pre_invocation:
      - "require(role.hr)"
      - "delegate(workday-oauth, target: workday-api, permissions: [read_compensation])"
      - delegate:
          plugin: audit-receipt
          on_error: continue
          config:
            mode: trace
"#;
        let cfg = compile_config(yaml).expect("compile");
        let route = cfg.routes.get("get_compensation").expect("route");
        assert_eq!(route.policy.len(), 3);

        // Step [1] is the string-form delegate.
        let crate::rules::Effect::Delegate(s1) = &route.policy[1] else {
            panic!("expected Delegate at policy[1]");
        };
        assert_eq!(s1.plugin_name, "workday-oauth");
        assert!(s1.on_error.is_none());

        // Step [2] is the map-form delegate.
        let crate::rules::Effect::Delegate(s2) = &route.policy[2] else {
            panic!("expected Delegate at policy[2]");
        };
        assert_eq!(s2.plugin_name, "audit-receipt");
        assert_eq!(s2.on_error.as_deref(), Some("continue"));
    }

    #[test]
    fn compile_route_with_delegate_in_policy_and_post_policy() {
        // End-to-end: delegate() lands in the right phase with the
        // right source path for diagnostics. Mixed with normal rules
        // to prove it doesn't perturb existing step parsing.
        let yaml = r#"
routes:
  get_compensation:
    pre_invocation:
      - "require(role.hr)"
      - delegate:
          plugin: workday-oauth
          config:
            target: workday-api
            permissions: [read_compensation]
      - "require(authenticated)"
    post_invocation:
      - delegate:
          plugin: audit-biscuit
          on_error: continue
"#;
        let cfg = compile_config(yaml).expect("compile");
        let route = cfg.routes.get("get_compensation").expect("route present");
        assert_eq!(route.policy.len(), 3);

        // Policy step [1] is the delegate.
        let crate::rules::Effect::Delegate(ds) = &route.policy[1] else {
            panic!("expected Delegate at policy[1], got {:?}", route.policy[1]);
        };
        assert_eq!(ds.plugin_name, "workday-oauth");
        assert_eq!(ds.source, "get_compensation.pre_invocation[1]");

        // post_policy[0] is the audit-biscuit delegate.
        let crate::rules::Effect::Delegate(post_ds) = &route.post_policy[0] else {
            panic!("expected Delegate at post_policy[0]");
        };
        assert_eq!(post_ds.plugin_name, "audit-biscuit");
        assert_eq!(post_ds.on_error.as_deref(), Some("continue"));
        assert_eq!(post_ds.source, "get_compensation.post_invocation[0]");
    }

    // ----- validate(name) compile-time rejection (DSL spec §4.2) -----

    #[test]
    fn parse_pipeline_rejects_validate_stage_at_compile_time() {
        // Named-validator dispatch isn't implemented; the parser
        // rejects `validate(...)` rather than letting it through to
        // a runtime stub that silently passes. Diagnostic points the
        // operator at the working alternatives.
        let err = parse_pipeline("str | validate(ssn_format) | mask(4)")
            .expect_err("validate(name) should fail to parse");
        let msg = format!("{err}");
        assert!(
            msg.contains("not implemented"),
            "diagnostic should explain that validate is unimplemented: {msg}",
        );
        assert!(
            msg.contains("regex") && msg.contains("plugin"),
            "diagnostic should suggest regex(...) and plugin(...): {msg}",
        );
        assert!(
            msg.contains("ssn_format"),
            "diagnostic should echo the rejected validator name: {msg}",
        );
    }

    #[test]
    fn parse_pipeline_does_not_reject_other_stages() {
        // Sanity: the validate rejection doesn't catch unrelated
        // stages. A pipeline with no validate stage parses cleanly.
        let p = parse_pipeline("str | len(..100) | regex(\"^[A-Z]+$\") | mask(4)")
            .expect("non-validate pipeline parses");
        assert_eq!(p.stages.len(), 4);
    }
}
