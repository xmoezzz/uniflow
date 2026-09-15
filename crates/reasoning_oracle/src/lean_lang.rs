//! A tiny, deliberately small expression language shared by every
//! `Domain::IntegerArithmetic` [`crate::ConstraintQuery`] — common C-family
//! syntax (`+ - * / % == != < <= > >= && || !`) plus the Python-flavored
//! spellings (`and`/`or`/`not`) so a caller doesn't need to transliterate
//! its source language first. This is NOT a general-purpose expression
//! parser for any real language — it only needs to cover the shape of
//! constraint expressions a taint/dataflow engine would actually ask about
//! (bounds checks, arithmetic comparisons, boolean combinations of them).

#[derive(Clone, Debug, PartialEq)]
pub enum Expr {
    Int(i64),
    Bool(bool),
    Var(String),
    Unary(UnOp, Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UnOp {
    Neg,
    Not,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Int(i64),
    Ident(String),
    Op(&'static str),
    LParen,
    RParen,
}

fn tokenize(input: &str) -> Result<Vec<Token>, ParseError> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '(' {
            tokens.push(Token::LParen);
            i += 1;
            continue;
        }
        if c == ')' {
            tokens.push(Token::RParen);
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && chars[i].is_ascii_digit() {
                i += 1;
            }
            let text: String = chars[start..i].iter().collect();
            tokens.push(Token::Int(text.parse().map_err(|_| ParseError(format!("invalid integer literal `{text}`")))?));
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            tokens.push(match word.as_str() {
                "and" => Token::Op("&&"),
                "or" => Token::Op("||"),
                "not" => Token::Op("!"),
                "true" | "True" => Token::Ident("true".to_string()),
                "false" | "False" => Token::Ident("false".to_string()),
                _ => Token::Ident(word),
            });
            continue;
        }
        let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
        if matches!(two.as_str(), "==" | "!=" | "<=" | ">=" | "&&" | "||") {
            tokens.push(Token::Op(match two.as_str() {
                "==" => "==",
                "!=" => "!=",
                "<=" => "<=",
                ">=" => ">=",
                "&&" => "&&",
                "||" => "||",
                _ => unreachable!(),
            }));
            i += 2;
            continue;
        }
        let op = match c {
            '+' => "+",
            '-' => "-",
            '*' => "*",
            '/' => "/",
            '%' => "%",
            '<' => "<",
            '>' => ">",
            '!' => "!",
            other => return Err(ParseError(format!("unexpected character `{other}`"))),
        };
        tokens.push(Token::Op(op));
        i += 1;
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        token
    }

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Op("||"))) {
            self.advance();
            let rhs = self.parse_and()?;
            lhs = Expr::Binary(BinOp::Or, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_comparison()?;
        while matches!(self.peek(), Some(Token::Op("&&"))) {
            self.advance();
            let rhs = self.parse_comparison()?;
            lhs = Expr::Binary(BinOp::And, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_comparison(&mut self) -> Result<Expr, ParseError> {
        let lhs = self.parse_additive()?;
        let op = match self.peek() {
            Some(Token::Op("==")) => Some(BinOp::Eq),
            Some(Token::Op("!=")) => Some(BinOp::Ne),
            Some(Token::Op("<")) => Some(BinOp::Lt),
            Some(Token::Op("<=")) => Some(BinOp::Le),
            Some(Token::Op(">")) => Some(BinOp::Gt),
            Some(Token::Op(">=")) => Some(BinOp::Ge),
            _ => None,
        };
        let Some(op) = op else { return Ok(lhs) };
        self.advance();
        let rhs = self.parse_additive()?;
        Ok(Expr::Binary(op, Box::new(lhs), Box::new(rhs)))
    }

    fn parse_additive(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_multiplicative()?;
        loop {
            let op = match self.peek() {
                Some(Token::Op("+")) => BinOp::Add,
                Some(Token::Op("-")) => BinOp::Sub,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_multiplicative()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_multiplicative(&mut self) -> Result<Expr, ParseError> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Some(Token::Op("*")) => BinOp::Mul,
                Some(Token::Op("/")) => BinOp::Div,
                Some(Token::Op("%")) => BinOp::Mod,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_unary()?;
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr, ParseError> {
        match self.peek() {
            Some(Token::Op("-")) => {
                self.advance();
                Ok(Expr::Unary(UnOp::Neg, Box::new(self.parse_unary()?)))
            }
            Some(Token::Op("!")) => {
                self.advance();
                Ok(Expr::Unary(UnOp::Not, Box::new(self.parse_unary()?)))
            }
            _ => self.parse_primary(),
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.advance() {
            Some(Token::Int(value)) => Ok(Expr::Int(value)),
            Some(Token::Ident(name)) if name == "true" => Ok(Expr::Bool(true)),
            Some(Token::Ident(name)) if name == "false" => Ok(Expr::Bool(false)),
            Some(Token::Ident(name)) => Ok(Expr::Var(name)),
            Some(Token::LParen) => {
                let inner = self.parse_or()?;
                match self.advance() {
                    Some(Token::RParen) => Ok(inner),
                    other => Err(ParseError(format!("expected `)`, found {other:?}"))),
                }
            }
            other => Err(ParseError(format!("expected an expression, found {other:?}"))),
        }
    }
}

pub fn parse(input: &str) -> Result<Expr, ParseError> {
    let tokens = tokenize(input)?;
    let mut parser = Parser { tokens, pos: 0 };
    let expr = parser.parse_or()?;
    if parser.pos != parser.tokens.len() {
        return Err(ParseError(format!("unexpected trailing tokens after `{input}`")));
    }
    Ok(expr)
}

/// Replaces every `Var` in `expr` whose name is a key of `values` with the
/// corresponding literal `Int` — used to turn a bounded existential into a
/// finite disjunction of concrete witnesses (`omega` decides disjunctions of
/// quantifier-free facts natively; it cannot synthesize an existential
/// witness itself, see `crate::lean::LeanOracle`). A variable absent from
/// `values` is left untouched.
pub fn substitute_ints(expr: &Expr, values: &std::collections::HashMap<String, i64>) -> Expr {
    match expr {
        Expr::Int(_) | Expr::Bool(_) => expr.clone(),
        Expr::Var(name) => match values.get(name) {
            Some(value) => Expr::Int(*value),
            None => expr.clone(),
        },
        Expr::Unary(op, inner) => Expr::Unary(*op, Box::new(substitute_ints(inner, values))),
        Expr::Binary(op, lhs, rhs) => Expr::Binary(*op, Box::new(substitute_ints(lhs, values)), Box::new(substitute_ints(rhs, values))),
    }
}

/// Every free variable `expr` references, in first-seen order.
pub fn free_vars(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Int(_) | Expr::Bool(_) => {}
        Expr::Var(name) => {
            if !out.contains(name) {
                out.push(name.clone());
            }
        }
        Expr::Unary(_, inner) => free_vars(inner, out),
        Expr::Binary(_, lhs, rhs) => {
            free_vars(lhs, out);
            free_vars(rhs, out);
        }
    }
}

/// Renders `expr` as Lean 4 syntax — comparisons/logical connectives become
/// `Prop`-level operators (`=`, `≠`, `∧`, `∨`, `¬`), arithmetic stays as
/// ordinary `Int` operators; Lean's own elaborator is trusted to reject a
/// genuinely ill-typed combination rather than this renderer duplicating
/// Lean's type discipline.
pub fn render_lean(expr: &Expr) -> String {
    match expr {
        Expr::Int(n) if *n < 0 => format!("(-{})", -n),
        Expr::Int(n) => n.to_string(),
        Expr::Bool(true) => "True".to_string(),
        Expr::Bool(false) => "False".to_string(),
        Expr::Var(name) => name.clone(),
        Expr::Unary(UnOp::Neg, inner) => format!("(-{})", render_lean(inner)),
        Expr::Unary(UnOp::Not, inner) => format!("(¬ {})", render_lean(inner)),
        Expr::Binary(op, lhs, rhs) => {
            let symbol = match op {
                BinOp::Add => "+",
                BinOp::Sub => "-",
                BinOp::Mul => "*",
                BinOp::Div => "/",
                BinOp::Mod => "%",
                BinOp::Eq => "=",
                BinOp::Ne => "\u{2260}",
                BinOp::Lt => "<",
                BinOp::Le => "\u{2264}",
                BinOp::Gt => ">",
                BinOp::Ge => "\u{2265}",
                BinOp::And => "\u{2227}",
                BinOp::Or => "\u{2228}",
            };
            format!("({} {} {})", render_lean(lhs), symbol, render_lean(rhs))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bounds_check_conjunction() {
        let expr = parse("x >= 0 && x < 256").unwrap();
        let mut vars = Vec::new();
        free_vars(&expr, &mut vars);
        assert_eq!(vars, vec!["x".to_string()]);
        assert_eq!(render_lean(&expr), "((x \u{2265} 0) \u{2227} (x < 256))");
    }

    #[test]
    fn parses_python_flavored_boolean_keywords() {
        let expr = parse("a == b and not (a != 0)").unwrap();
        assert_eq!(render_lean(&expr), "((a = b) \u{2227} (\u{00ac} (a \u{2260} 0)))");
    }

    #[test]
    fn respects_arithmetic_precedence() {
        let expr = parse("a + b * c == d").unwrap();
        assert_eq!(render_lean(&expr), "((a + (b * c)) = d)");
    }

    #[test]
    fn rejects_trailing_garbage() {
        assert!(parse("a == b )").is_err());
    }

    #[test]
    fn rejects_unknown_characters() {
        assert!(parse("a == b @ c").is_err());
    }

    #[test]
    fn substitute_ints_replaces_only_named_variables() {
        let expr = parse("x + y == 2").unwrap();
        let mut values = std::collections::HashMap::new();
        values.insert("x".to_string(), 3);
        let substituted = substitute_ints(&expr, &values);
        assert_eq!(render_lean(&substituted), "((3 + y) = 2)");
    }
}
