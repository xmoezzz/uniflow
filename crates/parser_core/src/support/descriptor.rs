// Language descriptor: the data that tells the generic engines how much of a
// language's surface syntax they may assume. Frontends supply one descriptor
// and, for constructs the descriptor cannot express, a [`LangHooks`] impl.

/// How a language delimits statement blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockStyle {
    /// `{ ... }`, with optional braces for single statements (C family).
    Braces,
    /// `do ... end`, `begin ... end`, `do ... done`, `fi`, `endif`.
    EndKeyword,
    /// No block at all: a single statement or expression (SQL, makefiles).
    None,
}

/// Keyword spellings a language uses for its control and declaration forms.
#[derive(Clone, Debug)]
pub struct Keywords {
    pub if_kw: &'static str,
    /// `else if` spellings, tried before `else`.
    pub else_if: &'static [&'static str],
    pub else_kw: Option<&'static str>,
    /// Inverse condition keyword (`unless`).
    pub unless: Option<&'static str>,
    pub while_kw: &'static str,
    pub until: Option<&'static str>,
    pub do_kw: Option<&'static str>,
    pub for_kw: &'static str,
    /// Extra keywords that also introduce a for-each (`foreach`, `loop`).
    pub foreach_kw: &'static [&'static str],
    /// Word separating the iteration variable from the iterable (`in`, `as`).
    pub in_kw: Option<&'static str>,
    pub switch_kw: &'static [&'static str],
    pub case_kw: Option<&'static str>,
    pub default_kw: Option<&'static str>,
    pub break_kw: &'static [&'static str],
    pub continue_kw: &'static [&'static str],
    pub return_kw: Option<&'static str>,
    pub throw_kw: &'static [&'static str],
    pub try_kw: Option<&'static str>,
    pub catch_kw: &'static [&'static str],
    pub finally_kw: &'static [&'static str],
    pub class_kw: &'static [&'static str],
    pub function_kw: &'static [&'static str],
    /// No-op statement keyword (`pass`, `noop`, `:`).
    pub pass_kw: &'static [&'static str],
    /// Keywords that end a block in `EndKeyword` languages.
    pub end_kw: &'static [&'static str],
    /// `then`/`do` words that may follow a condition.
    pub then_kw: &'static [&'static str],
}

impl Default for Keywords {
    fn default() -> Self {
        Self {
            if_kw: "if",
            else_if: &["else if"],
            else_kw: Some("else"),
            unless: None,
            while_kw: "while",
            until: None,
            do_kw: Some("do"),
            for_kw: "for",
            foreach_kw: &["foreach"],
            in_kw: Some("in"),
            switch_kw: &["switch", "select"],
            case_kw: Some("case"),
            default_kw: Some("default"),
            break_kw: &["break"],
            continue_kw: &["continue"],
            return_kw: Some("return"),
            throw_kw: &["throw"],
            try_kw: Some("try"),
            catch_kw: &["catch"],
            finally_kw: &["finally"],
            class_kw: &["class", "interface", "struct", "enum"],
            function_kw: &["function", "func", "def", "fn", "sub"],
            pass_kw: &[],
            end_kw: &["end", "endif", "endwhile", "endfor", "fi", "done"],
            then_kw: &["then", "do"],
        }
    }
}

/// Operator surface used by the expression engine.
#[derive(Clone, Debug)]
pub struct ExprOps {
    /// Binary operators with their binding power (higher binds tighter).
    pub binary: &'static [(&'static str, u8)],
    /// Prefix operators.
    pub prefix: &'static [(&'static str, uniflow_hir::UnaryOp)],
    /// Compound assignment operators (`+=`, `.=`), mapped to the binary op they
    /// stand for so the assigned value keeps its data dependencies.
    pub compound: &'static [(&'static str, uniflow_hir::BinaryOp)],
    pub assignment_ops: &'static [&'static str],
    /// `a ? b : c` / `a ?? b`.
    pub ternary: bool,
    /// `and`/`or`/`not` word operators (Python, Ruby, SQL).
    pub word_logic: bool,
    /// String concatenation operator that is not `+` (PHP `.`).
    pub concat_op: Option<&'static str>,
    /// Range operators, modeled as calls so their operands stay connected.
    pub range_ops: &'static [&'static str],
    /// `is`, `in`, `isa`, `instanceof`, `new`-style postfix keywords.
    pub relational_keywords: &'static [&'static str],
    /// Call/lambda arrow operators (`=>`, `->`).
    pub lambda_arrows: &'static [&'static str],
}

impl Default for ExprOps {
    fn default() -> Self {
        Self {
            binary: &[
                ("||", 1),
                ("&&", 2),
                ("|", 3),
                ("^", 4),
                ("&", 5),
                ("==", 6),
                ("!=", 6),
                ("===", 6),
                ("!==", 6),
                ("<", 7),
                (">", 7),
                ("<=", 7),
                (">=", 7),
                ("<<", 8),
                (">>", 8),
                ("+", 9),
                ("-", 9),
                ("*", 10),
                ("/", 10),
                ("%", 10),
                ("**", 11),
            ],
            prefix: &[
                ("-", uniflow_hir::UnaryOp::Neg),
                ("!", uniflow_hir::UnaryOp::Not),
                ("~", uniflow_hir::UnaryOp::BitNot),
                ("+", uniflow_hir::UnaryOp::Neg),
            ],
            compound: &[
                ("+=", uniflow_hir::BinaryOp::Add),
                ("-=", uniflow_hir::BinaryOp::Sub),
                ("*=", uniflow_hir::BinaryOp::Mul),
                ("/=", uniflow_hir::BinaryOp::Div),
                ("%=", uniflow_hir::BinaryOp::Mod),
                ("&=", uniflow_hir::BinaryOp::BitAnd),
                ("|=", uniflow_hir::BinaryOp::BitOr),
                ("^=", uniflow_hir::BinaryOp::BitXor),
                ("<<=", uniflow_hir::BinaryOp::BitAnd),
                (">>=", uniflow_hir::BinaryOp::BitOr),
            ],
            assignment_ops: &["=", "="],
            ternary: true,
            word_logic: false,
            concat_op: None,
            range_ops: &[],
            relational_keywords: &[],
            lambda_arrows: &["=>"],
        }
    }
}

/// Everything the generic engines need to know about one language.
#[derive(Clone, Debug)]
pub struct LangDescriptor {
    pub language: uniflow_hir::Language,
    pub lexer: LexerSpec,
    pub kw: Keywords,
    pub ops: ExprOps,
    pub block_style: BlockStyle,
    /// Statements end at a newline as well as (or instead of) `;`.
    pub newline_terminated: bool,
    /// `let`/`var`/`val`/`my`/`local` style declaration introducers.
    pub decl_introducers: &'static [&'static str],
    /// Go's `:=` short declaration.
    pub walrus: Option<&'static str>,
    /// Declarations introduce a type annotation with this token (`:` or `as`).
    pub type_annotation: Option<&'static str>,
    /// Type comes before the name (C, Java, C#, ObjC).
    pub type_before_name: bool,
    /// `this`/`self`/`$this` spellings that map to the receiver symbol.
    pub self_names: &'static [&'static str],
    /// Member-access operators, in addition to `.` (`->`, `::`, `?.`, `&.`).
    pub member_ops: &'static [&'static str],
    /// `(Type) expr` casts are meaningful in this language.
    pub c_casts: bool,
    /// `f(name: value)` names arguments rather than building an object literal.
    pub named_arguments: bool,
    /// `k => v` pairs inside a literal (PHP, Go, Rust-ish maps).
    pub map_fat_arrow: bool,
    /// `puts x` / `system cmd` — calls without parentheses.
    pub implicit_call_parens: bool,
    /// `func (r *T) Name()` — a receiver clause before the method name (Go).
    pub receiver_in_parens: bool,
    /// Methods are named `Class.method` in the HIR.
    pub methods_qualified: bool,
    /// Globals are referenced with a sigil (`$GLOBALS`, `$`, `global`).
    pub global_prefixes: &'static [&'static str],
    /// `for (init; cond; step)` support.
    pub c_style_for: bool,
    /// `while` written after the statement (`cmd while cond`, `begin .. end while`).
    pub trailing_while: bool,
    /// Trailing conditional execution (`cmd if cond`, Ruby/Shell).
    pub trailing_if: bool,
    /// `?x` / `x?` truthiness test forms.
    pub optional_chaining: bool,
    /// Operators that create a new scope-only symbol when used in a declaration.
    pub increment_ops: &'static [&'static str],
    /// Language-specific statement keywords handled by hooks.
    pub hook_statements: &'static [&'static str],
    /// Statement terminators that may be omitted before a `}`.
    pub optional_final_terminator: bool,
    /// `case` bodies fall through unless they break (C, Java, C#, PHP).
    pub switch_falls_through: bool,
}

impl LangDescriptor {
    pub fn new(language: uniflow_hir::Language) -> Self {
        Self {
            language,
            lexer: LexerSpec::default(),
            kw: Keywords::default(),
            ops: ExprOps::default(),
            block_style: BlockStyle::Braces,
            newline_terminated: false,
            decl_introducers: &[],
            walrus: None,
            type_annotation: None,
            type_before_name: false,
            self_names: &["this"],
            member_ops: &["?."],
            c_casts: true,
            named_arguments: false,
            map_fat_arrow: false,
            implicit_call_parens: false,
            receiver_in_parens: false,
            methods_qualified: true,
            global_prefixes: &[],
            c_style_for: true,
            trailing_while: false,
            trailing_if: false,
            optional_chaining: false,
            increment_ops: &["++", "--"],
            hook_statements: &[],
            optional_final_terminator: true,
            switch_falls_through: true,
        }
    }

    pub fn binary_precedence(&self, op: &str) -> Option<u8> {
        if let Some((_, power)) = self.ops.binary.iter().find(|(name, _)| *name == op) {
            return Some(*power);
        }
        if self.ops.concat_op == Some(op) {
            // Concatenation binds like addition.
            return Some(9);
        }
        if self.ops.word_logic {
            match op {
                "or" => return Some(1),
                "and" => return Some(2),
                _ => {}
            }
        }
        if self.ops.range_ops.contains(&op) {
            return Some(1);
        }
        if self.ops.word_logic && self.ops.relational_keywords.contains(&op) {
            return Some(7);
        }
        if self.ops.relational_keywords.contains(&op) {
            return Some(7);
        }
        None
    }

    pub fn is_statement_end_word(&self, text: &str) -> bool {
        self.kw.end_kw.contains(&text)
    }
}

/// Lexical scopes. Symbol names resolve innermost first; the bottom layer holds
/// file-level names (functions, globals, imported types).
#[derive(Clone, Debug, Default)]
pub struct Scope {
    layers: Vec<std::collections::HashMap<String, uniflow_hir::SymbolId>>,
}

impl Scope {
    pub fn new() -> Self {
        Self {
            layers: vec![std::collections::HashMap::new()],
        }
    }

    pub fn push(&mut self) {
        self.layers.push(Default::default());
    }

    pub fn pop(&mut self) {
        if self.layers.len() > 1 {
            self.layers.pop();
        }
    }

    pub fn depth(&self) -> usize {
        self.layers.len()
    }

    pub fn get(&self, name: &str) -> Option<uniflow_hir::SymbolId> {
        self.layers.iter().rev().find_map(|layer| layer.get(name).copied())
    }

    pub fn define(&mut self, name: &str, symbol: uniflow_hir::SymbolId) {
        let index = self.layers.len().saturating_sub(1);
        self.layers[index].insert(name.to_string(), symbol);
    }

    /// Define in the outermost layer so the name is visible file-wide.
    pub fn define_file(&mut self, name: &str, symbol: uniflow_hir::SymbolId) {
        self.layers[0].insert(name.to_string(), symbol);
    }

    /// Snapshot and restore, used when a function body ends.
    pub fn save(&self) -> Vec<std::collections::HashMap<String, uniflow_hir::SymbolId>> {
        self.layers.clone()
    }

    pub fn restore(&mut self, saved: Vec<std::collections::HashMap<String, uniflow_hir::SymbolId>>) {
        self.layers = saved;
    }

    pub fn names(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .layers
            .iter()
            .flat_map(|layer| layer.keys().cloned())
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

/// Per-language extension point for constructs the descriptor cannot express
/// (`defer`/`go` in Go, `rescue` modifiers in Ruby, pipelines in Shell, SQL
/// statements, JSP tags).
///
/// Hooks receive the parser by reference, so they can call back into the generic
/// engines (`parse_block`, `parse_expression`) without borrow conflicts.
pub trait LangHooks {
    /// Parse a statement. Return `Ok(None)` to let the generic engine try.
    fn statement(
        &mut self,
        _parser: &mut crate::support::Pg<'_>,
    ) -> anyhow::Result<Option<uniflow_hir::Stmt>> {
        Ok(None)
    }

    /// Parse a top-level item (class, function, module-level directive).
    fn item(&mut self, _parser: &mut crate::support::Pg<'_>) -> anyhow::Result<bool> {
        Ok(false)
    }

    /// Extend a primary expression with language-specific postfix syntax.
    fn postfix(
        &mut self,
        _parser: &mut crate::support::Pg<'_>,
        _base: uniflow_hir::Expr,
    ) -> anyhow::Result<Option<uniflow_hir::Expr>> {
        Ok(None)
    }
}

/// Hook set for languages with no extensions beyond the descriptor.
#[derive(Default)]
pub struct NoHooks;

impl LangHooks for NoHooks {}
