fn infer_call_return_type(call: &CallExpr, receiver_ty: Option<&str>) -> Option<String> {
    match &call.target {
        CallTarget::Named(name) => {
            if let Some(ty) = receiver_ty {
                if let Some(method) = name.rsplit('.').next() {
                    if matches!(method, "append" | "add" | "put" | "push") {
                        return Some(ty.to_string());
                    }
                    if method == "pop" {
                        if let Some(inner) = ty.strip_prefix("list<").and_then(|rest| rest.strip_suffix('>')) {
                            return Some(inner.to_string());
                        }
                        if let Some(inner) = ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                            if let Some((_, value)) = inner.split_once(',') {
                                return Some(value.trim().to_string());
                            }
                        }
                    }
                    if matches!(method, "get" | "setdefault") {
                        if let Some(inner) = ty.strip_prefix("dict<").and_then(|rest| rest.strip_suffix('>')) {
                            if let Some((_, value)) = inner.split_once(',') {
                                return Some(value.trim().to_string());
                            }
                        }
                    }
                    if method == "copy" {
                        return Some(ty.to_string());
                    }
                    if method == "dumps" && ty == "json" {
                        return Some("str".to_string());
                    }
                }
            }
            if let Some((prefix, method)) = name.rsplit_once('.') {
                if method == "builder" || method == "newBuilder" {
                    return Some(prefix.to_string());
                }
            }
            match name.as_str() {
                "str" | "java.lang.String.valueOf" => Some("String".to_string()),
                "json.dumps" => Some("str".to_string()),
                _ => None,
            }
        }
        _ => None,
    }
}

fn ir_return_type_name(ty: &Type) -> Option<&str> {
    match ty {
        Type::Void | Type::Unknown => None,
        Type::Bool => Some("boolean"),
        Type::Int => Some("int"),
        Type::Float => Some("double"),
        Type::String => Some("java.lang.String"),
        Type::Object(name) => Some(name.as_str()),
        Type::Function => Some("Function"),
    }
}

fn lower_callee(target: &CallTarget) -> Callee {
    match target {
        CallTarget::Named(name) => Callee::Static(name.clone()),
        CallTarget::Dynamic(_) => Callee::Unknown,
        CallTarget::Resolved(symbol) => Callee::Static(format!("symbol#{}", symbol.0)),
    }
}

fn lower_type_name(name: Option<&str>) -> Type {
    match name.unwrap_or("unknown") {
        "void" => Type::Void,
        "bool" | "boolean" => Type::Bool,
        "int" | "i32" | "i64" => Type::Int,
        "float" | "double" => Type::Float,
        "String" | "str" | "java.lang.String" => Type::String,
        other => Type::Object(other.to_string()),
    }
}


