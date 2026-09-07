use super::{JavaSyntax, Range, TokKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JavaDeclarationKind { Class, Interface, Enum, Record, AnonymousClass, Method, Constructor, Field, Initializer }

/// A declaration's owner is its immediate declaring type, never a containing
/// method or an unrelated enclosing type. Initializer expressions are not members.
#[derive(Clone, Debug)]
pub struct JavaDeclaration {
    pub kind: JavaDeclarationKind,
    pub range: Range<usize>,
    pub owner: Option<usize>,
    pub is_member: bool,
    pub name: String,
    pub names: Vec<String>,
    pub modifiers: Vec<String>,
    pub annotations: Vec<String>,
    pub marker_annotations: Vec<String>,
    pub annotation_arguments: Vec<(String, String)>,
    pub declared_type: String,
    pub superclass: String,
    pub interfaces: Vec<String>,
    pub parameters: Option<Range<usize>>,
    pub body: Option<Range<usize>>,
    pub has_throws: bool,
}

impl JavaDeclaration {
    fn new(kind: JavaDeclarationKind, range: Range<usize>, owner: Option<usize>) -> Self {
        Self { kind, range, owner, is_member: false, name: String::new(), names: Vec::new(),
            modifiers: Vec::new(), annotations: Vec::new(), marker_annotations: Vec::new(),
            annotation_arguments: Vec::new(), declared_type: String::new(),
            superclass: String::new(), interfaces: Vec::new(), parameters: None, body: None, has_throws: false }
    }
}

impl JavaSyntax {
    pub(super) fn index_declarations(&mut self) {
        self.declaration_region(0, self.tokens.len() - 1, None, false, 0);
    }

    fn declaration_prefix(&self, mut at: usize, end: usize) -> (usize, Vec<String>, Vec<String>, Vec<String>, Vec<(String, String)>) {
        let mut modifiers = Vec::new();
        let mut annotations = Vec::new();
        let mut markers = Vec::new();
        let mut arguments = Vec::new();
        while at < end {
            if self.csharp_attributes && self.is(at, "[") {
                let Some(close) = self.mates[at] else { break; };
                let mut part = at + 1;
                // A target (`return:`, `method:`, ...) is not an attribute name.
                if self.is(part + 1, ":") { part += 2; }
                while part < close {
                    let name_start = part;
                    while part < close && !self.is(part, "(") && !self.is(part, ",") {
                        part += 1;
                    }
                    let name = self.token_text(name_start, part);
                    if !name.is_empty() {
                        annotations.push(name.clone());
                        if self.is(part, "(") {
                            if let Some(args_end) = self.mates[part] {
                                arguments.push((name, self.token_text(part + 1, args_end)));
                                part = args_end + 1;
                            } else { break; }
                        } else { markers.push(name); }
                    }
                    if self.is(part, ",") { part += 1; } else { break; }
                }
                at = close + 1;
            } else if self.is(at, "@") && !self.is(at + 1, "interface") {
                at += 1;
                let mut name = String::new();
                if at < end { name.push_str(&self.tokens[at].text); at += 1; }
                while at + 1 < end && self.is(at, ".") {
                    name.push('.'); name.push_str(&self.tokens[at + 1].text); at += 2;
                }
                if !self.is(at, "(") { markers.push(name.clone()); }
                annotations.push(name);
                if self.is(at, "(") {
                    if let Some(close) = self.mates[at] {
                        arguments.push((annotations.last().unwrap().clone(), self.token_text(at + 1, close)));
                        at = close + 1;
                    } else { at += 1; }
                }
            } else if matches!(self.tokens[at].text.as_str(), "public" | "protected" | "private"
                | "static" | "final" | "abstract" | "native" | "synchronized" | "strictfp"
                | "transient" | "volatile" | "default" | "sealed")
            {
                modifiers.push(self.tokens[at].text.clone()); at += 1;
            } else if self.is(at, "non") && self.is(at + 1, "-") && self.is(at + 2, "sealed") {
                modifiers.push("non-sealed".into()); at += 3;
            } else { break; }
        }
        (at, modifiers, annotations, markers, arguments)
    }

    fn declaration_region(&mut self, mut start: usize, end: usize, owner: Option<usize>, is_member: bool, depth: usize) {
        use JavaDeclarationKind as D;
        if depth > 256 { return; }
        while start < end {
            if self.is(start, ";") { start += 1; continue; }
            let (mut head, modifiers, annotations, markers, arguments) = self.declaration_prefix(start, end);
            if self.is(head, "@") && self.is(head + 1, "interface") { head += 1; }
            let kind = match self.tokens.get(head).map(|t| t.text.as_str()) {
                Some("class") => Some(D::Class), Some("interface") => Some(D::Interface),
                Some("enum") => Some(D::Enum), Some("record") => Some(D::Record), _ => None,
            };
            if let Some(kind) = kind {
                let mut open = head + 2;
                while open < end && !self.is(open, "{") && !self.is(open, ";") {
                    open = self.mates[open].filter(|&c| c > open).map_or(open + 1, |c| c + 1);
                }
                if let Some(close) = self.mates.get(open).copied().flatten().filter(|&c| c < end) {
                    let mut declaration = JavaDeclaration::new(kind, self.range(start, close + 1), owner);
                    declaration.name = self.tokens[head + 1].text.clone();
                    declaration.is_member = is_member;
                    declaration.modifiers = modifiers; declaration.annotations = annotations;
                    declaration.marker_annotations = markers;
                    declaration.annotation_arguments = arguments;
                    self.type_bases(head + 2, open, &mut declaration);
                    let id = self.declarations.len(); self.declarations.push(declaration);
                    self.declaration_region(open + 1, close, Some(id), true, depth + 1);
                    start = close + 1; continue;
                }
            }
            // Skip initializer blocks, but discover types declared inside them.
            if self.is(head, "{") {
                if let Some(close) = self.mates[head] {
                    let mut declaration = JavaDeclaration::new(D::Initializer, self.range(start, close + 1), owner);
                    declaration.is_member = is_member;
                    declaration.modifiers = modifiers;
                    self.declarations.push(declaration);
                    self.embedded_declarations(head + 1, close, owner, depth + 1);
                    start = close + 1; continue;
                }
            }
            let mut cursor = head;
            let mut initializer = false;
            let mut method = None;
            while cursor < end {
                if self.is(cursor, "=") { initializer = true; }
                if self.is(cursor, "(") && !initializer && cursor > head
                    && self.tokens[cursor - 1].kind == TokKind::Ident
                { method = Some(cursor); break; }
                if self.is(cursor, ";") { break; }
                if let Some(close) = self.mates[cursor].filter(|&c| c > cursor) {
                    if self.is(cursor, "{") {
                        self.embedded_declarations(cursor, close + 1, owner, depth + 1);
                    }
                    cursor = close + 1;
                } else { cursor += 1; }
            }
            if let Some(params) = method {
                if let Some(close_params) = self.mates[params] {
                    let mut body = close_params + 1;
                    while body < end && !self.is(body, "{") && !self.is(body, ";") { body += 1; }
                    let next = if self.is(body, "{") { self.mates[body].map_or(body + 1, |c| c + 1) }
                        else { (body + 1).min(end) };
                    let name = self.tokens[params - 1].text.clone();
                    let constructor = owner.is_some_and(|id| self.declarations[id].name == name);
                    let mut declaration = JavaDeclaration::new(if constructor { D::Constructor } else { D::Method },
                        self.range(start, next), owner);
                    declaration.name = name;
                    declaration.is_member = is_member;
                    declaration.modifiers = modifiers; declaration.annotations = annotations;
                    declaration.marker_annotations = markers;
                    declaration.annotation_arguments = arguments;
                    declaration.parameters = Some(self.range(params + 1, close_params));
                    if self.is(body, "{") { declaration.body = Some(self.range(body, next)); }
                    declaration.has_throws = (close_params + 1..body).any(|i| self.is(i, "throws"));
                    declaration.declared_type = self.token_text(head, params - 1);
                    if owner.is_some() { self.declarations.push(declaration); }
                    if self.is(body, "{") && next > body + 1 {
                        self.embedded_declarations(body + 1, next - 1, owner, depth + 1);
                    }
                    start = next.max(start + 1); continue;
                }
            }
            if owner.is_some() && cursor < end && self.is(cursor, ";") && head < cursor {
                let mut field = JavaDeclaration::new(D::Field, self.range(start, cursor + 1), owner);
                field.is_member = is_member;
                field.modifiers = modifiers; field.annotations = annotations;
                field.marker_annotations = markers;
                field.annotation_arguments = arguments;
                self.field_declarators(head, cursor, &mut field);
                if !field.names.is_empty() { self.declarations.push(field); }
            }
            start = (cursor + 1).max(start + 1);
        }
    }

    fn token_text(&self, start: usize, end: usize) -> String {
        self.tokens[start..end].iter().map(|t| t.text.as_str()).collect()
    }

    fn type_bases(&self, mut at: usize, end: usize, declaration: &mut JavaDeclaration) {
        let mut angle = 0i32;
        let mut mode = "";
        let mut name = String::new();
        while at <= end {
            let word = if at == end { "," } else { self.tokens[at].text.as_str() };
            if angle == 0 && matches!(word, "extends" | "implements" | "permits" | ",") {
                if !name.is_empty() {
                    if mode == "extends" { declaration.superclass = std::mem::take(&mut name); }
                    else if mode == "implements" { declaration.interfaces.push(std::mem::take(&mut name)); }
                    else { name.clear(); }
                }
                if word != "," { mode = word; }
            } else if word == "<" { angle += 1; }
            else if matches!(word, ">" | ">>" | ">>>") { angle = (angle - word.len() as i32).max(0); }
            else if angle == 0 && !mode.is_empty() && (word == "." || self.tokens.get(at).is_some_and(|t| t.kind == TokKind::Ident)) {
                name.push_str(word);
            }
            if at < end && self.is(at, "(") { at = self.mates[at].unwrap_or(at); }
            at += 1;
        }
    }

    fn field_declarators(&self, start: usize, end: usize, field: &mut JavaDeclaration) {
        let mut at = start;
        let mut segment = start;
        let mut angle = 0i32;
        let mut assigned = false;
        let mut name_end = None;
        while at <= end {
            let word = if at == end { "," } else { self.tokens[at].text.as_str() };
            if !assigned && word == "<" { angle += 1; }
            if !assigned && matches!(word, ">" | ">>" | ">>>") { angle = (angle - word.len() as i32).max(0); }
            if angle == 0 && word == "=" && !assigned { name_end = Some(at); assigned = true; }
            if angle == 0 && word == "," {
                let until = name_end.unwrap_or(at);
                if let Some(name) = (segment..until).rev().find(|&i| self.tokens[i].kind == TokKind::Ident) {
                    if !field.names.is_empty() || name > start {
                        if field.names.is_empty() {
                            field.declared_type = self.token_text(start, name);
                            // Java permits array brackets on either the declared type
                            // (`String[] a`) or each declarator (`String a[]`).
                            for _ in (name + 1..until).filter(|&i| self.is(i, "[")) {
                                field.declared_type.push_str("[]");
                            }
                        }
                        field.names.push(self.tokens[name].text.clone());
                    }
                }
                segment = at + 1; assigned = false; name_end = None;
            }
            at = self.mates.get(at).copied().flatten().filter(|&c| c > at).map_or(at + 1, |c| c + 1);
        }
    }

    fn embedded_declarations(&mut self, mut at: usize, end: usize, owner: Option<usize>, depth: usize) {
        if depth > 256 { return; }
        while at < end {
            let (head, _, _, _, _) = self.declaration_prefix(at, end);
            if ["class", "interface", "enum", "record"].iter().any(|word| self.is(head, word))
                && !at.checked_sub(1).is_some_and(|i| self.is(i, "."))
            {
                let mut open = head + 2;
                while open < end && !self.is(open, "{") {
                    open = self.mates[open].filter(|&c| c > open).map_or(open + 1, |c| c + 1);
                }
                if let Some(close) = self.mates.get(open).copied().flatten().filter(|&c| c < end) {
                    self.declaration_region(at, close + 1, owner, false, depth + 1);
                    at = close + 1; continue;
                }
            }
            if self.is(at, "{") && self.anonymous_creation(at).is_some() {
                if let Some(close) = self.mates[at] {
                    let (creation, params, close_params) = self.anonymous_creation(at).unwrap();
                    let id = self.declarations.len();
                    let mut declaration = JavaDeclaration::new(JavaDeclarationKind::AnonymousClass,
                        self.range(creation, close + 1), owner);
                    declaration.parameters = Some(self.range(params + 1, close_params));
                    self.declarations.push(declaration);
                    self.declaration_region(at + 1, close, Some(id), true, depth + 1);
                    at = close + 1; continue;
                }
            }
            at += 1;
        }
    }

    fn anonymous_creation(&self, open: usize) -> Option<(usize, usize, usize)> {
        if open == 0 || !self.is(open - 1, ")") { return None; }
        let close_params = open - 1;
        let params = self.mates[close_params]?;
        for at in (0..params).rev() {
            if self.is(at, "new") { return Some((at, params, close_params)); }
            if matches!(self.tokens[at].text.as_str(), ";" | "{" | "}" | "=" | "(" | ")"
                | "if" | "for" | "while" | "switch" | "synchronized" | "catch" | "try") { return None; }
        }
        None
    }
}
