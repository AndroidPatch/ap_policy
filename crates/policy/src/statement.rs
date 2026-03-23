//! Policy statement parser
//!
//! This module provides parsing for SELinux policy statements.

use std::fmt::{self, Write};
use std::io::{BufRead, Cursor};
use std::iter::Peekable;
use std::vec::IntoIter;

use crate::{SePolicy, Xperm};

/// Token for policy statement parsing
#[derive(Debug, Clone, PartialEq)]
pub enum Token<'a> {
    AL,
    DN,
    AA,
    DA,
    AX,
    AY,
    DX,
    PM,
    EF,
    TA,
    TY,
    AT,
    TT,
    TC,
    TM,
    GF,
    LB,
    RB,
    CM,
    ST,
    TL,
    HP,
    HX(u16),
    ID(&'a str),
}

type Tokens<'a> = Peekable<IntoIter<Token<'a>>>;
type ParseResult<'a, T> = Result<T, ParseError<'a>>;

/// Parse error
#[derive(Debug)]
pub enum ParseError<'a> {
    General,
    AvtabAv(Token<'a>),
    AvtabXperms(Token<'a>),
    AvtabType(Token<'a>),
    TypeState(Token<'a>),
    TypeAttr,
    TypeTrans,
    NewType,
    NewAttr,
    GenfsCon,
    ShowHelp,
    UnknownAction(Token<'a>),
}

impl std::error::Error for ParseError<'_> {}

impl fmt::Display for ParseError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::General => write!(f, "General parse error"),
            ParseError::AvtabAv(action) => {
                write!(f, "{action} *source_type *target_type *class *perm_set")
            }
            ParseError::AvtabXperms(action) => {
                write!(
                    f,
                    "{action} *source_type *target_type *class operation xperm_set"
                )
            }
            ParseError::AvtabType(action) => {
                write!(f, "{action} source_type target_type class default_type")
            }
            ParseError::TypeState(action) => {
                write!(f, "{action} *type")
            }
            ParseError::TypeAttr => f.write_str("typeattribute ^type ^attribute"),
            ParseError::TypeTrans => f.write_str(
                "type_transition source_type target_type class default_type (object_name)",
            ),
            ParseError::NewType => f.write_str("type type_name ^(attribute)"),
            ParseError::NewAttr => f.write_str("attribute attribute_name"),
            ParseError::GenfsCon => f.write_str("genfscon fs_name partial_path fs_context"),
            ParseError::ShowHelp => format_statement_help(f),
            ParseError::UnknownAction(action) => write!(f, "Unknown action: \"{action}\""),
        }
    }
}

impl fmt::Display for Token<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::AL => f.write_str("allow"),
            Token::DN => f.write_str("deny"),
            Token::AA => f.write_str("auditallow"),
            Token::DA => f.write_str("dontaudit"),
            Token::AX => f.write_str("allowxperm"),
            Token::AY => f.write_str("auditallowxperm"),
            Token::DX => f.write_str("dontauditxperm"),
            Token::PM => f.write_str("permissive"),
            Token::EF => f.write_str("enforce"),
            Token::TA => f.write_str("typeattribute"),
            Token::TY => f.write_str("type"),
            Token::AT => f.write_str("attribute"),
            Token::TT => f.write_str("type_transition"),
            Token::TC => f.write_str("type_change"),
            Token::TM => f.write_str("type_member"),
            Token::GF => f.write_str("genfscon"),
            Token::LB => f.write_char('{'),
            Token::RB => f.write_char('}'),
            Token::CM => f.write_char(','),
            Token::ST => f.write_char('*'),
            Token::TL => f.write_char('~'),
            Token::HP => f.write_char('-'),
            Token::HX(n) => write!(f, "{n:06X}"),
            Token::ID(s) => f.write_str(s),
        }
    }
}

fn parse_id<'a>(tokens: &mut Tokens<'a>) -> ParseResult<'a, &'a str> {
    match tokens.next() {
        Some(Token::ID(name)) => Ok(name),
        _ => Err(ParseError::General)?,
    }
}

fn parse_term<'a>(tokens: &mut Tokens<'a>) -> ParseResult<'a, Vec<&'a str>> {
    match tokens.next() {
        Some(Token::ID(name)) => Ok(vec![name]),
        Some(Token::LB) => {
            let mut names = Vec::new();
            loop {
                match tokens.next() {
                    Some(Token::ID(name)) => names.push(name),
                    Some(Token::RB) => break,
                    _ => return Err(ParseError::General)?,
                }
            }
            Ok(names)
        }
        _ => Err(ParseError::General)?,
    }
}

fn parse_sterm<'a>(tokens: &mut Tokens<'a>) -> ParseResult<'a, Vec<&'a str>> {
    match tokens.next() {
        Some(Token::ID(name)) => Ok(vec![name]),
        Some(Token::ST) => Ok(vec![]),
        Some(Token::LB) => {
            let mut names = Some(Vec::new());
            loop {
                match tokens.next() {
                    Some(Token::ID(name)) => {
                        if let Some(ref mut names) = names {
                            names.push(name)
                        }
                    }
                    Some(Token::ST) => names = None,
                    Some(Token::RB) => break,
                    _ => return Err(ParseError::General)?,
                }
            }
            Ok(names.unwrap_or_default())
        }
        _ => Err(ParseError::General)?,
    }
}

fn parse_xperm<'a>(tokens: &mut Tokens<'a>) -> ParseResult<'a, Xperm> {
    let low = match tokens.next() {
        Some(Token::HX(low)) => low,
        _ => return Err(ParseError::General)?,
    };
    let high = match tokens.peek() {
        Some(Token::HP) => {
            tokens.next();
            match tokens.next() {
                Some(Token::HX(high)) => high,
                _ => return Err(ParseError::General)?,
            }
        }
        _ => low,
    };
    Ok(Xperm { low, high, reset: false })
}

fn parse_xperms<'a>(tokens: &mut Tokens<'a>) -> ParseResult<'a, Vec<Xperm>> {
    let mut xperms = Vec::new();
    let reset = match tokens.peek() {
        Some(Token::TL) => {
            tokens.next();
            if !matches!(tokens.peek(), Some(Token::LB)) {
                return Err(ParseError::General)?;
            }
            true
        }
        _ => false,
    };
    match tokens.next() {
        Some(Token::LB) => {
            loop {
                let mut xperm = parse_xperm(tokens)?;
                xperm.reset = reset;
                xperms.push(xperm);
                if matches!(tokens.peek(), Some(Token::RB)) {
                    tokens.next();
                    break;
                }
            }
        }
        Some(Token::ST) => {
            xperms.push(Xperm {
                low: 0x0000,
                high: 0xFFFF,
                reset,
            });
        }
        Some(Token::HX(low)) => {
            if low > 0 {
                xperms.push(Xperm { low, high: low, reset });
            } else {
                xperms.push(Xperm {
                    low: 0x0000,
                    high: 0xFFFF,
                    reset,
                });
            }
        }
        _ => return Err(ParseError::General)?,
    }
    Ok(xperms)
}

fn match_string<'a>(tokens: &mut Tokens<'a>, pattern: &str) -> ParseResult<'a, ()> {
    if let Some(Token::ID(s)) = tokens.next() {
        if s == pattern {
            return Ok(());
        }
    }
    Err(ParseError::General)
}

fn extract_token<'a>(s: &'a str, tokens: &mut Vec<Token<'a>>) {
    match s {
        "allow" => tokens.push(Token::AL),
        "deny" => tokens.push(Token::DN),
        "auditallow" => tokens.push(Token::AA),
        "dontaudit" => tokens.push(Token::DA),
        "allowxperm" => tokens.push(Token::AX),
        "auditallowxperm" => tokens.push(Token::AY),
        "dontauditxperm" => tokens.push(Token::DX),
        "permissive" => tokens.push(Token::PM),
        "enforce" => tokens.push(Token::EF),
        "typeattribute" => tokens.push(Token::TA),
        "type" => tokens.push(Token::TY),
        "attribute" => tokens.push(Token::AT),
        "type_transition" => tokens.push(Token::TT),
        "type_change" => tokens.push(Token::TC),
        "type_member" => tokens.push(Token::TM),
        "genfscon" => tokens.push(Token::GF),
        "*" => tokens.push(Token::ST),
        "" => {}
        _ => {
            if let Some(idx) = s.find('{') {
                let (a, b) = s.split_at(idx);
                extract_token(a, tokens);
                tokens.push(Token::LB);
                extract_token(&b[1..], tokens);
            } else if let Some(idx) = s.find('}') {
                let (a, b) = s.split_at(idx);
                extract_token(a, tokens);
                tokens.push(Token::RB);
                extract_token(&b[1..], tokens);
            } else if let Some(idx) = s.find(',') {
                let (a, b) = s.split_at(idx);
                extract_token(a, tokens);
                tokens.push(Token::CM);
                extract_token(&b[1..], tokens);
            } else if let Some(idx) = s.find('-') {
                let (a, b) = s.split_at(idx);
                extract_token(a, tokens);
                tokens.push(Token::HP);
                extract_token(&b[1..], tokens);
            } else if let Some(s) = s.strip_prefix('~') {
                tokens.push(Token::TL);
                extract_token(s, tokens);
            } else if let Some(s) = s.strip_prefix("0x") {
                tokens.push(Token::HX(s.parse().unwrap_or(0)));
            } else {
                tokens.push(Token::ID(s));
            }
        }
    }
}

fn tokenize_statement(statement: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    for s in statement.split_whitespace() {
        extract_token(s, &mut tokens);
    }
    tokens
}

/// Parse and execute a statement on the policy
pub fn parse_statement(policy: &mut SePolicy, statement: &str) {
    let statement = statement.trim();
    if statement.is_empty() || statement.starts_with('#') {
        return;
    }
    let mut tokens = tokenize_statement(statement).into_iter().peekable();
    match exec_statement(policy, &mut tokens) {
        Ok(()) => {}
        Err(e) => {
            eprintln!("Syntax error in: \"{}\"", statement);
            eprintln!("Hint: {}", e);
        }
    }
}

/// Parse multiple rules from a string
pub fn parse_rules(policy: &mut SePolicy, rules: &str) {
    let cursor = Cursor::new(rules.as_bytes());
    for line in cursor.lines() {
        if let Ok(line) = line {
            parse_statement(policy, &line);
        }
    }
}

fn exec_statement<'a>(policy: &mut SePolicy, tokens: &mut Tokens<'a>) -> ParseResult<'a, ()> {
    let action = match tokens.next() {
        Some(token) => token,
        None => return Err(ParseError::ShowHelp)?,
    };

    let check_additional_args = |tokens: &mut Tokens<'a>| {
        if tokens.peek().is_none() {
            Ok(())
        } else {
            Err(ParseError::General)
        }
    };

    match action {
        Token::AL | Token::DN | Token::AA | Token::DA => {
            let s = parse_sterm(tokens)?;
            let t = parse_sterm(tokens)?;
            let c = parse_sterm(tokens)?;
            let p = parse_sterm(tokens)?;
            check_additional_args(tokens)?;
            match action {
                Token::AL => policy.allow(&s, &t, &c, &p),
                Token::DN => policy.deny(&s, &t, &c, &p),
                Token::AA => policy.auditallow(&s, &t, &c, &p),
                Token::DA => policy.dontaudit(&s, &t, &c, &p),
                _ => unreachable!(),
            }
        }
        Token::AX | Token::AY | Token::DX => {
            let s = parse_sterm(tokens)?;
            let t = parse_sterm(tokens)?;
            let c = parse_sterm(tokens)?;
            match_string(tokens, "ioctl")?;
            let p = parse_xperms(tokens)?;
            check_additional_args(tokens)?;
            match action {
                Token::AX => policy.allowxperm(&s, &t, &c, &p),
                Token::AY => policy.auditallowxperm(&s, &t, &c, &p),
                Token::DX => policy.dontauditxperm(&s, &t, &c, &p),
                _ => unreachable!(),
            }
        }
        Token::PM | Token::EF => {
            let t = parse_sterm(tokens)?;
            check_additional_args(tokens)?;
            match action {
                Token::PM => policy.permissive(&t),
                Token::EF => policy.enforce(&t),
                _ => unreachable!(),
            }
        }
        Token::TA => {
            let t = parse_term(tokens)?;
            let a = parse_term(tokens)?;
            check_additional_args(tokens)?;
            policy.typeattribute(&t, &a);
        }
        Token::TY => {
            let t = parse_id(tokens)?;
            let a = if tokens.peek().is_none() {
                vec![]
            } else {
                parse_term(tokens)?
            };
            check_additional_args(tokens)?;
            policy.type_(t, &a);
        }
        Token::AT => {
            let t = parse_id(tokens)?;
            check_additional_args(tokens)?;
            policy.attribute(t);
        }
        Token::TC | Token::TM => {
            let s = parse_id(tokens)?;
            let t = parse_id(tokens)?;
            let c = parse_id(tokens)?;
            let d = parse_id(tokens)?;
            check_additional_args(tokens)?;
            match action {
                Token::TC => policy.type_change(s, t, c, d),
                Token::TM => policy.type_member(s, t, c, d),
                _ => unreachable!(),
            }
        }
        Token::TT => {
            let s = parse_id(tokens)?;
            let t = parse_id(tokens)?;
            let c = parse_id(tokens)?;
            let d = parse_id(tokens)?;
            let o = if tokens.peek().is_none() {
                ""
            } else {
                parse_id(tokens)?
            };
            check_additional_args(tokens)?;
            policy.type_transition(s, t, c, d, o);
        }
        Token::GF => {
            let s = parse_id(tokens)?;
            let t = parse_id(tokens)?;
            let c = parse_id(tokens)?;
            check_additional_args(tokens)?;
            policy.genfscon(s, t, c);
        }
        _ => return Err(ParseError::UnknownAction(action))?,
    }
    Ok(())
}

/// Format statement help text
pub fn format_statement_help(f: &mut dyn Write) -> fmt::Result {
    write!(
        f,
        r#"** Policy statements:

One policy statement should be treated as a single parameter;
this means each policy statement should be enclosed in quotes.
Multiple policy statements can be provided in a single command.

Statements has a format of "<rule_name> [args...]".
Arguments labeled with (^) can accept one or more entries.
Multiple entries consist of a space separated list enclosed in braces ({{}}).
Arguments labeled with (*) are the same as (^), but additionally
support the match-all operator (*).

Example: "allow {{ s1 s2 }} {{ t1 t2 }} class *"
Will be expanded to:

allow s1 t1 class {{ all-permissions-of-class }}
allow s1 t2 class {{ all-permissions-of-class }}
allow s2 t1 class {{ all-permissions-of-class }}
allow s2 t2 class {{ all-permissions-of-class }}

** Extended permissions:

The only supported operation for extended permissions right now is 'ioctl'.
xperm_set is one or multiple hexadecimal numeric values ranging from 0x0000 to 0xFFFF.
Multiple values consist of a space separated list enclosed in braces ({{}}).
Use the complement operator (~) to specify all permissions except those explicitly listed.
Use the range operator (-) to specify all permissions within the low – high range.
Use the match all operator (*) to match all ioctl commands (0x0000-0xFFFF).
The special value 0 is used to clear all rules.

Some examples:
allowxperm source target class ioctl 0x8910
allowxperm source target class ioctl {{ 0x8910-0x8926 0x892A-0x8935 }}
allowxperm source target class ioctl ~{{ 0x8910 0x892A }}
allowxperm source target class ioctl *

** Supported policy statements:

{}
{}
{}
{}
{}
{}
{}
{}
{}
{}
{}
{}
{}
{}
{}
{}
"#,
        ParseError::AvtabAv(Token::AL),
        ParseError::AvtabAv(Token::DN),
        ParseError::AvtabAv(Token::AA),
        ParseError::AvtabAv(Token::DA),
        ParseError::AvtabXperms(Token::AX),
        ParseError::AvtabXperms(Token::AY),
        ParseError::AvtabXperms(Token::DX),
        ParseError::TypeState(Token::PM),
        ParseError::TypeState(Token::EF),
        ParseError::TypeAttr,
        ParseError::NewType,
        ParseError::NewAttr,
        ParseError::TypeTrans,
        ParseError::AvtabType(Token::TC),
        ParseError::AvtabType(Token::TM),
        ParseError::GenfsCon
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_statement() {
        let tokens = tokenize_statement("allow source target class permission");
        assert_eq!(tokens.len(), 4);
        assert!(matches!(tokens[0], Token::AL));
        assert!(matches!(tokens[1], Token::ID("source")));
    }

    #[test]
    fn test_tokenize_braces() {
        let tokens = tokenize_statement("allow { s1 s2 } target class *");
        assert!(matches!(tokens[0], Token::AL));
        assert!(matches!(tokens[1], Token::LB));
        assert!(matches!(tokens[7], Token::ST));
    }
}
