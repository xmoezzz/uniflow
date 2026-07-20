
fn looks_like_python_type_annotation(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.contains('(') || trimmed.starts_with(|c: char| c == '\'' || c == '"') {
        return false;
    }
    matches!(trimmed,
        "Never" | "typing.Never" | "typing_extensions.Never" |
        "NoReturn" | "typing.NoReturn" | "Self" | "typing.Self" |
        "typing_extensions.Self" | "LiteralString" | "typing.LiteralString"
    ) || has_top_level_separator(trimmed, '|')
        || [
            "Optional[", "typing.Optional[", "Annotated[", "typing.Annotated[",
            "typing_extensions.Annotated[", "Union[", "typing.Union[",
            "ClassVar[", "Final[", "Required[", "NotRequired[", "Literal[",
            "TypeGuard[", "TypeIs[", "type[", "Type[", "list[", "List[",
            "Sequence[", "MutableSequence[", "Collection[", "Iterable[",
            "set[", "Set[", "tuple[", "Tuple[", "Iterator[", "AsyncIterator[",
            "Generator[", "AsyncGenerator[", "Awaitable[", "Coroutine[",
            "Concatenate[", "Unpack[", "Callable[", "dict[", "Dict[",
            "Mapping[", "MutableMapping[", "Mapped[", "QuerySet[", "Manager[",
        ].iter().any(|prefix| trimmed.starts_with(prefix))
}

fn normalize_python_annotation_type(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    project_index: Option<&PyProjectIndex>,
) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(inner) = trimmed.strip_prefix("Optional[").and_then(|rest| rest.strip_suffix(']')) {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if let Some(inner) = trimmed.strip_prefix("typing.Optional[").and_then(|rest| rest.strip_suffix(']')) {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if let Some(inner) = trimmed.strip_prefix("Annotated[").and_then(|rest| rest.strip_suffix(']')) {
        let parts = split_top_level_commas(inner);
        return parts.first().and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index));
    }
    if let Some(inner) = trimmed.strip_prefix("typing.Annotated[").and_then(|rest| rest.strip_suffix(']')) {
        let parts = split_top_level_commas(inner);
        return parts.first().and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index));
    }
    if let Some(inner) = trimmed.strip_prefix("typing_extensions.Annotated[").and_then(|rest| rest.strip_suffix(']')) {
        let parts = split_top_level_commas(inner);
        return parts.first().and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index));
    }
    if let Some(inner) = trimmed.strip_prefix("Optional[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Optional[").and_then(|rest| rest.strip_suffix(']')))
    {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if has_top_level_separator(trimmed, '|') {
        for part in split_top_level_separator(trimmed, '|') {
            let part = part.trim();
            if matches!(part, "None" | "NoneType") {
                continue;
            }
            if let Some(ty) = normalize_python_annotation_type(part, module_name, imports, project_index) {
                return Some(ty);
            }
        }
    }
    if let Some(inner) = trimmed.strip_prefix("Union[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Union[").and_then(|rest| rest.strip_suffix(']')))
    {
        for part in split_top_level_commas(inner) {
            let part = part.trim();
            if matches!(part, "None" | "NoneType") {
                continue;
            }
            if let Some(ty) = normalize_python_annotation_type(part, module_name, imports, project_index) {
                return Some(ty);
            }
        }
    }
    if let Some(inner) = trimmed.strip_prefix("ClassVar[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.ClassVar[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Final[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Final[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Required[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("NotRequired[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Required[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.NotRequired[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.Required[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.NotRequired[").and_then(|rest| rest.strip_suffix(']')))
    {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if matches!(trimmed, "Never" | "typing.Never" | "typing_extensions.Never" | "NoReturn" | "typing.NoReturn") {
        return Some("none".to_string());
    }
    if let Some(inner) = trimmed.strip_prefix("TypeIs[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.TypeIs[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.TypeIs[").and_then(|rest| rest.strip_suffix(']')))
    {
        let _ = inner;
        return Some("bool".to_string());
    }
    if let Some(inner) = trimmed.strip_prefix("Literal[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Literal[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.Literal[").and_then(|rest| rest.strip_suffix(']')))
    {
        let parts = split_top_level_commas(inner);
        if let Some(first) = parts.first() {
            let first = first.trim();
            if is_string_literal(first) {
                return Some("str".to_string());
            }
            if is_int_literal(first) {
                return Some("int".to_string());
            }
            if matches!(first, "True" | "False") {
                return Some("bool".to_string());
            }
            return normalize_python_annotation_type(first, module_name, imports, project_index);
        }
    }
    if matches!(trimmed, "LiteralString" | "typing.LiteralString" | "typing_extensions.LiteralString") {
        return Some("str".to_string());
    }
    if let Some(inner) = trimmed.strip_prefix("TypeGuard[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.TypeGuard[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.TypeGuard[").and_then(|rest| rest.strip_suffix(']')))
    {
        let _ = inner;
        return Some("bool".to_string());
    }
    if matches!(trimmed, "Self" | "typing.Self" | "typing_extensions.Self") {
        return Some("Self".to_string());
    }
    if matches!(trimmed, "TypedDict" | "typing.TypedDict" | "typing_extensions.TypedDict") {
        return Some("dict".to_string());
    }
    if let Some(inner) = trimmed.strip_prefix("type[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("Type[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Type[").and_then(|rest| rest.strip_suffix(']')))
    {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if let Some(inner) = trimmed.strip_prefix("list[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("List[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.List[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Sequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Sequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Sequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("MutableSequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.MutableSequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.MutableSequence[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Collection[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Collection[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Collection[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Iterable[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Iterable[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Iterable[").and_then(|rest| rest.strip_suffix(']')))
    {
        let item = normalize_python_annotation_type(inner, module_name, imports, project_index)
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("list<{item}>"));
    }
    if let Some(inner) = trimmed.strip_prefix("set[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("Set[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Set[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("MutableSet[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.MutableSet[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.MutableSet[").and_then(|rest| rest.strip_suffix(']')))
    {
        let item = normalize_python_annotation_type(inner, module_name, imports, project_index)
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("set<{item}>"));
    }
    if let Some(inner) = trimmed.strip_prefix("tuple[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("Tuple[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Tuple[").and_then(|rest| rest.strip_suffix(']')))
    {
        let items = split_top_level_commas(inner)
            .into_iter()
            .filter_map(|part| normalize_python_annotation_type(&part, module_name, imports, project_index))
            .collect::<Vec<_>>();
        if !items.is_empty() {
            return Some(format!("tuple<{}>", items.join("|")));
        }
    }
    if let Some(inner) = trimmed.strip_prefix("Iterator[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Iterator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Iterator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("AsyncIterator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.AsyncIterator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.AsyncIterator[").and_then(|rest| rest.strip_suffix(']')))
    {
        let item = normalize_python_annotation_type(inner, module_name, imports, project_index)
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("generator<{item}>"));
    }
    if let Some(inner) = trimmed.strip_prefix("Generator[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Generator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("AsyncGenerator[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.AsyncGenerator[").and_then(|rest| rest.strip_suffix(']')))
    {
        let item = split_top_level_commas(inner)
            .into_iter()
            .next()
            .and_then(|part| normalize_python_annotation_type(&part, module_name, imports, project_index))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("generator<{item}>"));
    }
    if let Some(inner) = trimmed.strip_prefix("Awaitable[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Awaitable[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Awaitable[").and_then(|rest| rest.strip_suffix(']')))
    {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if let Some(inner) = trimmed.strip_prefix("Coroutine[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Coroutine[").and_then(|rest| rest.strip_suffix(']')))
    {
        let parts = split_top_level_commas(inner);
        if let Some(ret) = parts.get(2).and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index)) {
            return Some(ret);
        }
    }
    if let Some(inner) = trimmed.strip_prefix("Concatenate[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Concatenate[").and_then(|rest| rest.strip_suffix(']')))
    {
        let parts = split_top_level_commas(inner);
        if let Some(last) = parts.last() {
            return normalize_python_annotation_type(last, module_name, imports, project_index);
        }
    }
    if let Some(inner) = trimmed.strip_prefix("Unpack[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Unpack[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing_extensions.Unpack[").and_then(|rest| rest.strip_suffix(']')))
    {
        return normalize_python_annotation_type(inner, module_name, imports, project_index);
    }
    if let Some(inner) = trimmed.strip_prefix("Callable[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("typing.Callable[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Callable[").and_then(|rest| rest.strip_suffix(']')))
    {
        if let Some((_params, ret)) = split_once_top_level(inner, ',') {
            let ret = normalize_python_annotation_type(ret.trim(), module_name, imports, project_index)
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("callable<{}>", ret));
        }
        return Some("callable<unknown>".to_string());
    }
    if let Some(inner) = trimmed.strip_prefix("dict[").and_then(|rest| rest.strip_suffix(']'))
        .or_else(|| trimmed.strip_prefix("Dict[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Dict[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("Mapping[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.Mapping[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("typing.MutableMapping[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("MutableMapping[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.Mapping[").and_then(|rest| rest.strip_suffix(']')))
        .or_else(|| trimmed.strip_prefix("collections.abc.MutableMapping[").and_then(|rest| rest.strip_suffix(']')))
    {
        let parts = split_top_level_commas(inner);
        let key_ty = parts
            .first()
            .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
            .unwrap_or_else(|| "unknown".to_string());
        let value_ty = parts
            .get(1)
            .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
            .unwrap_or_else(|| "unknown".to_string());
        return Some(format!("dict<{key_ty},{value_ty}>"));
    }
    if let Some((base, inner)) = split_python_generic_annotation(trimmed) {
        if matches!(base.as_str(), "defaultdict" | "DefaultDict" | "typing.DefaultDict" | "collections.defaultdict") {
            let parts = split_top_level_commas(&inner);
            let key_ty = parts
                .first()
                .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
                .unwrap_or_else(|| "unknown".to_string());
            let value_ty = parts
                .get(1)
                .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("dict<{},{}>", key_ty, value_ty));
        }
        if matches!(base.as_str(), "deque" | "Deque" | "typing.Deque" | "collections.deque") {
            let parts = split_top_level_commas(&inner);
            let item = parts
                .first()
                .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("list<{}>", item));
        }
        if matches!(base.as_str(), "Counter" | "typing.Counter" | "collections.Counter") {
            let parts = split_top_level_commas(&inner);
            let item = parts
                .first()
                .and_then(|part| normalize_python_annotation_type(part, module_name, imports, project_index))
                .unwrap_or_else(|| "unknown".to_string());
            return Some(format!("dict<{},int>", item));
        }
        if matches!(base.as_str(), "Mapped" | "sqlalchemy.orm.Mapped" | "DynamicMapped" | "WriteOnlyMapped" | "InstrumentedAttribute" | "MappedColumn") {
            let parts = split_top_level_commas(&inner);
            if let Some(first) = parts.first() {
                return normalize_python_annotation_type(first, module_name, imports, project_index);
            }
        }
        if matches!(base.as_str(), "QuerySet" | "Manager" | "django.db.models.QuerySet" | "django.db.models.Manager") {
            let parts = split_top_level_commas(&inner);
            if let Some(first) = parts.first() {
                let item = normalize_python_annotation_type(first, module_name, imports, project_index)
                    .unwrap_or_else(|| "unknown".to_string());
                return Some(format!("list<{item}>"));
            }
        }
        if matches!(base.as_str(), "TypeAliasType" | "typing.TypeAliasType" | "typing_extensions.TypeAliasType") {
            let parts = split_top_level_commas(&inner);
            if let Some(target) = parts.get(1) {
                return normalize_python_annotation_type(target, module_name, imports, project_index);
            }
        }
        if let Some(index) = project_index {
            if let Some(canonical_base) = qualify_type_name(module_name, &base, imports, Some(index)) {
                if index.class_exists(&canonical_base) || index.is_protocol_class(&canonical_base) {
                    let args = split_top_level_commas(&inner)
                        .into_iter()
                        .filter_map(|part| normalize_python_annotation_type(&part, module_name, imports, project_index))
                        .collect::<Vec<_>>();
                    if !args.is_empty() {
                        return Some(format!("{}<{}>", canonical_base, args.join(",")));
                    }
                    return Some(canonical_base);
                }
            }
        }
    }
    if let Some(index) = project_index {
        if let Some(local_ty) = index.module_value_type(module_name, trimmed) {
            return Some(canonicalize_project_path(index, &local_ty));
        }
        if let Some(mapped) = imports.aliases.get(trimmed) {
            let canonical = canonicalize_project_path(index, mapped);
            if let Some(ty) = index.module_value_type_by_path(&canonical) {
                return Some(canonicalize_project_path(index, &ty));
            }
        }
        if let Some(in_module) = index.resolve_module_member(module_name, trimmed) {
            let canonical = canonicalize_project_path(index, &in_module);
            if let Some(ty) = index.module_value_type_by_path(&canonical) {
                return Some(canonicalize_project_path(index, &ty));
            }
        }
        if trimmed.contains('.') {
            if let Some(canonical) = canonicalize_prefixed_project_path(index, trimmed) {
                if let Some(ty) = index.module_value_type_by_path(&canonical) {
                    return Some(canonicalize_project_path(index, &ty));
                }
            }
        }
    }
    if matches!(trimmed, "str" | "int" | "float" | "bool" | "bytes") {
        return Some(trimmed.to_string());
    }
    qualify_type_name(module_name, trimmed, imports, project_index)
}


fn infer_python_field_factory_type(
    text: &str,
    module_name: &str,
    imports: &PyImports,
    project_index: Option<&PyProjectIndex>,
    known_classes: &HashSet<String>,
) -> Option<String> {
    let (callee, arg_text) = parse_call_parts(text.trim())?;
    let resolved = imports.aliases.get(&callee).map(String::as_str).unwrap_or(callee.as_str());
    if !matches!(
        resolved,
        "field" | "dataclasses.field" | "Field" | "pydantic.Field" | "sqlmodel.Field"
            | "attr.ib" | "attr.field" | "attrs.field"
    ) {
        return None;
    }
    let args = split_top_level_commas(&arg_text);
    if let Some(factory) = args.iter().find_map(|arg| {
        let (name, value) = split_python_keyword_arg(arg)?;
        matches!(name.as_str(), "default_factory" | "factory").then_some(value)
    }) {
        let factory = factory.trim();
        let builtin = match factory {
            "list" => Some("list"),
            "dict" => Some("dict"),
            "set" => Some("set"),
            "tuple" => Some("tuple"),
            _ => None,
        };
        if let Some(builtin) = builtin {
            return Some(builtin.to_string());
        }
        if let Some(index) = project_index {
            if let Some(ty) = infer_project_expr_type(
                factory,
                module_name,
                imports,
                index,
                &HashMap::new(),
                None,
            ) {
                return Some(ty);
            }
        }
        if known_classes.contains(factory)
            || factory.chars().next().is_some_and(|ch| ch.is_ascii_uppercase())
        {
            return Some(qualify_local_python_type(factory, module_name, known_classes));
        }
        if let Some(mapped) = imports.aliases.get(factory) {
            return Some(mapped.clone());
        }
    }
    if let Some(default_expr) = args.iter().find_map(|arg| {
        let (name, value) = split_python_keyword_arg(arg)?;
        (name == "default").then_some(value)
    }) {
        if default_expr.trim() != "None" {
            if let Some(index) = project_index {
                if let Some(ty) = infer_project_expr_type(
                    &default_expr,
                    module_name,
                    imports,
                    index,
                    &HashMap::new(),
                    None,
                ) {
                    return Some(ty);
                }
            }
        }
    }
    None
}

fn parse_class_body_annotated_field(line: &str) -> Option<(String, String, Option<String>)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.contains(":=") {
        return None;
    }
    let (left, rest) = split_once_top_level(trimmed, ':')?;
    let name = left.trim();
    if !is_simple_ident(name) {
        return None;
    }
    if let Some((annotation, value)) = split_once_top_level(&rest, '=') {
        return Some((
            name.to_string(),
            annotation.trim().to_string(),
            Some(value.trim().to_string()),
        ));
    }
    Some((name.to_string(), rest.trim().to_string(), None))
}

fn is_typed_dict_base_name(name: &str) -> bool {
    matches!(name, "TypedDict" | "typing.TypedDict" | "typing_extensions.TypedDict")
        || name.ends_with(".TypedDict")
}

fn is_named_tuple_base_name(name: &str) -> bool {
    matches!(name, "NamedTuple" | "typing.NamedTuple") || name.ends_with(".NamedTuple")
}

fn is_protocol_base_name(name: &str) -> bool {
    matches!(name, "Protocol" | "typing.Protocol" | "typing_extensions.Protocol")
        || name.ends_with(".Protocol")
}

fn parse_python_string_literal_content(text: &str) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let bytes = trimmed.as_bytes();
    let first = bytes[0] as char;
    let last = *bytes.last()? as char;
    if (first == '\'' || first == '"') && first == last {
        return Some(trimmed[1..trimmed.len().saturating_sub(1)].to_string());
    }
    None
}

fn extract_functional_type_decls(
    source: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> Vec<(String, HashMap<String, String>, String)> {
    let mut out = Vec::new();
    for raw_line in source.lines() {
        let indent = raw_line.chars().take_while(|c| c.is_whitespace()).count();
        let line = raw_line.trim();
        if indent != 0 || line.is_empty() || line.starts_with('#') || line.starts_with("def ") || line.starts_with("class ") || line.starts_with('@') {
            continue;
        }
        let Some((left, right)) = split_once_top_level(line, '=') else { continue; };
        let name = left.trim();
        if !is_simple_ident(name) {
            continue;
        }
        let Some((callee_text, arg_text)) = parse_call_parts(right.trim()) else { continue; };
        let args = split_python_call_args(&arg_text);
        if matches!(callee_text.as_str(), "TypedDict" | "typing.TypedDict" | "typing_extensions.TypedDict") {
            let declared_name = args.get(0).and_then(|arg| parse_python_string_literal_content(arg));
            if declared_name.as_deref() != Some(name) {
                continue;
            }
            let mut fields = HashMap::new();
            if let Some(spec_text) = args.get(1) {
                let spec = spec_text.trim();
                if spec.starts_with('{') && spec.ends_with('}') {
                    let inner = &spec[1..spec.len().saturating_sub(1)];
                    for entry in split_top_level_commas(inner) {
                        let Some((key, value)) = split_once_top_level(&entry, ':') else { continue; };
                        let Some(field_name) = parse_python_string_literal_content(&key) else { continue; };
                        if let Some(field_ty) = normalize_python_annotation_type(&value, module_name, imports, Some(index)) {
                            fields.insert(field_name, field_ty);
                        }
                    }
                }
            }
            out.push((name.to_string(), fields, "typed_dict".to_string()));
            continue;
        }
        if matches!(callee_text.as_str(), "NamedTuple" | "typing.NamedTuple") {
            let declared_name = args.get(0).and_then(|arg| parse_python_string_literal_content(arg));
            if declared_name.as_deref() != Some(name) {
                continue;
            }
            let mut fields = HashMap::new();
            if let Some(spec_text) = args.get(1) {
                let spec = spec_text.trim();
                if spec.starts_with('[') && spec.ends_with(']') {
                    let inner = &spec[1..spec.len().saturating_sub(1)];
                    for entry in split_top_level_commas(inner) {
                        let entry = entry.trim();
                        if !entry.starts_with('(') || !entry.ends_with(')') {
                            continue;
                        }
                        let pair = &entry[1..entry.len().saturating_sub(1)];
                        let parts = split_top_level_commas(pair);
                        if parts.len() < 2 {
                            continue;
                        }
                        let Some(field_name) = parse_python_string_literal_content(&parts[0]) else { continue; };
                        if let Some(field_ty) = normalize_python_annotation_type(&parts[1], module_name, imports, Some(index)) {
                            fields.insert(field_name, field_ty);
                        }
                    }
                }
            }
            out.push((name.to_string(), fields, "named_tuple".to_string()));
        }
    }
    out
}

fn infer_relation_target_type(
    target_expr: &str,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Option<String> {
    let trimmed = target_expr.trim();
    if let Some(lit) = strip_python_string_literal(trimmed) {
        if lit == "self" {
            if let Some(current_class) = current_class {
                return Some(current_class.to_string());
            }
        }
        if let Some(ty) = normalize_python_annotation_type(&lit, module_name, imports, Some(index)) {
            return Some(ty);
        }
        return qualify_type_name(module_name, &lit, imports, Some(index));
    }
    infer_project_expr_type(trimmed, module_name, imports, index, current_fields, current_class)
        .or_else(|| normalize_python_annotation_type(trimmed, module_name, imports, Some(index)))
}

fn infer_relation_constructor_type(
    callee_text: &str,
    args: &[String],
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_fields: &HashMap<String, String>,
    current_class: Option<&str>,
) -> Option<String> {
    let base_callee = split_last_top_level_dot(callee_text)
        .map(|(_, tail)| tail)
        .unwrap_or_else(|| callee_text.to_string());
    let singular = matches!(
        base_callee.as_str(),
        "relationship" | "ForeignKey" | "OneToOneField" | "Mapped" | "mapped_column"
    );
    let mut plural = matches!(base_callee.as_str(), "ManyToManyField");
    if !singular && !plural {
        return None;
    }
    let target_arg = args.iter().find_map(|arg| {
        if let Some((name, value)) = split_python_keyword_arg(arg) {
            if matches!(name.as_str(), "argument" | "to" | "model" | "target") {
                return Some(value);
            }
            return None;
        }
        Some(arg.clone())
    })?;
    let mut target_ty = infer_relation_target_type(&target_arg, module_name, imports, index, current_fields, current_class)?;
    if target_ty == "self" {
        if let Some(current_class) = current_class {
            target_ty = current_class.to_string();
        }
    }
    for arg in args {
        if let Some((name, value)) = split_python_keyword_arg(arg) {
            if name == "uselist" && matches!(value.trim(), "True" | "1") {
                plural = true;
            }
            if name == "collection_class" && matches!(value.trim(), "list" | "set" | "InstrumentedList") {
                plural = true;
            }
        }
    }
    if plural {
        target_ty = format!("list<{}>", target_ty);
    }
    Some(target_ty)
}

fn infer_project_class_body_fields(
    class: &PyClassText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let current_class = qualify_class_name(module_name, &class.name, Some(index));
    for raw_line in class.body.lines() {
        let indent = raw_line.chars().take_while(|c| c.is_whitespace()).count();
        let line = raw_line.trim();
        if indent != class.indent + 4
            || line.is_empty()
            || line.starts_with('#')
            || line.starts_with("def ")
            || line.starts_with("async def ")
            || line.starts_with('@')
            || line.starts_with("class ")
        {
            continue;
        }
        if let Some((name, annotation, value)) = parse_class_body_annotated_field(line) {
            if let Some(ty) = normalize_python_annotation_type(&annotation, module_name, imports, Some(index))
                .or_else(|| value.as_deref().and_then(|expr| infer_project_expr_type(expr, module_name, imports, index, &HashMap::new(), Some(&current_class))))
            {
                fields.insert(name, ty);
            }
            continue;
        }
        if let Some((left, right)) = split_once_top_level(line, '=') {
            let name = left.trim();
            if !name.contains('.') && is_simple_ident(name) {
                if let Some(ty) = infer_project_expr_type(&right, module_name, imports, index, &HashMap::new(), Some(&current_class)) {
                    fields.insert(name.to_string(), ty);
                }
            }
        }
    }
    fields
}

fn normalize_py_decorator_name(text: &str) -> String {
    let trimmed = text.trim().trim_start_matches('@').trim();
    trimmed
        .split_once('(')
        .map(|(name, _)| name.trim().to_string())
        .unwrap_or_else(|| trimmed.to_string())
}

fn function_has_decorator(func: &PyFunctionText, decorator: &str) -> bool {
    func.decorators.iter().any(|raw| {
        let name = normalize_py_decorator_name(raw);
        name == decorator || name.ends_with(&format!(".{decorator}"))
    })
}

fn property_decorator_target(func: &PyFunctionText, suffix: &str) -> Option<String> {
    let needle = format!(".{suffix}");
    func.decorators.iter().find_map(|raw| {
        let name = normalize_py_decorator_name(raw);
        let base = name.strip_suffix(&needle)?;
        base.rsplit('.').next().map(|part| part.to_string())
    })
}

fn parse_python_name_declaration(line: &str, prefix: &str) -> Option<Vec<String>> {
    let rest = line.trim().strip_prefix(prefix)?.trim();
    if rest.is_empty() {
        return None;
    }
    let names = split_top_level_commas(rest)
        .into_iter()
        .map(|name| name.trim().to_string())
        .filter(|name| is_simple_ident(name))
        .collect::<Vec<_>>();
    (!names.is_empty()).then_some(names)
}

fn seed_declared_global_name(
    builder: Option<&mut ModuleBuilder>,
    env: &mut PyEnv,
    name: &str,
) {
    let symbol = if let Some(existing) = env.vars.get(name).copied() {
        existing
    } else if let Some(builder) = builder {
        let created = builder.add_symbol(name, SymbolKind::Local);
        env.vars.insert(name.to_string(), created);
        created
    } else if let Some(existing) = env.capturable_vars.get(name).copied() {
        env.vars.insert(name.to_string(), existing);
        existing
    } else {
        return;
    };
    env.capturable_vars.entry(name.to_string()).or_insert(symbol);
    if let Some(member) = env.project_index.resolve_module_member(&env.current_module, name) {
        let canonical = canonicalize_project_path(&env.project_index, &member);
        if env.project_index.function_path_exists(&canonical) {
            env.callable_aliases.insert(name.to_string(), env.project_index.resolve_canonical_member_path(&canonical, &mut HashSet::new()));
            env.types.insert(name.to_string(), canonical);
        } else if env.project_index.class_exists(&canonical) || env.project_index.module_exists(&canonical) {
            env.types.insert(name.to_string(), canonical);
        } else if let Some(ty) = env.project_index.module_value_type_by_path(&member) {
            env.types.insert(name.to_string(), ty);
        }
    }
}

fn infer_project_known_classes(index: &PyProjectIndex) -> HashSet<String> {
    let mut out = index.classes_by_simple.keys().cloned().collect::<HashSet<_>>();
    for names in index.classes_by_module.values() {
        out.extend(names.iter().cloned());
    }
    out
}

fn seed_project_inference_env(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
) -> (PyEnv, HashSet<String>) {
    let mut env = PyEnv::default();
    env.current_module = module_name.to_string();
    env.current_class = current_class.map(|value| value.to_string());
    env.current_class_bases = current_class_bases.to_vec();
    env.current_function = current_class
        .map(|owner| format!("{owner}.{}", func.name))
        .unwrap_or_else(|| format!("{module_name}.{}", func.name));
    env.project_index = index.clone();
    env.executed_modules.insert(module_name.to_string());
    // Make project-wide class and monkey-patched field knowledge available to
    // every function.  Restricting this map to the current class caused calls
    // through locally constructed objects and imported classes to degrade to
    // synthetic `Owner.field.method` paths.
    env.class_field_index = index.field_types.clone();
    env.field_types = current_fields.clone();
    if let Some(owner) = current_class {
        env.class_field_index.insert(owner.to_string(), current_fields.clone());
    }

    let param_specs = parse_python_param_specs(&func.params);
    let is_staticmethod = function_has_decorator(func, "staticmethod");
    let is_classmethod = function_has_decorator(func, "classmethod");
    for (idx, spec) in param_specs.iter().enumerate() {
        let treat_as_receiver = idx == 0
            && current_class.is_some()
            && !is_staticmethod
            && (spec.name == "self" || spec.name == "cls" || is_classmethod);
        if treat_as_receiver {
            if let Some(owner) = current_class {
                env.types.insert(spec.name.clone(), owner.to_string());
            }
            env.self_name = Some(spec.name.clone());
            env.local_object_aliases.insert(spec.name.clone(), spec.name.clone());
            continue;
        }

        let annotation_ty = spec.annotation.as_deref().and_then(|annotation| {
            normalize_python_annotation_type(annotation, module_name, imports, Some(index))
        });
        let default_ty = spec.default_expr.as_deref().and_then(|default_expr| {
            infer_project_expr_type(
                default_expr,
                module_name,
                imports,
                index,
                &env.field_types,
                current_class,
            )
            .or_else(|| infer_simple_python_type(default_expr, imports, &env, &infer_project_known_classes(index)))
        });
        if let Some(ty) = annotation_ty.or(default_ty) {
            let canonical = canonicalize_project_path(index, &ty);
            env.types.insert(spec.name.clone(), canonical.clone());
            if index.function_path_exists(&canonical) {
                env.callable_aliases.insert(
                    spec.name.clone(),
                    index.resolve_canonical_member_path(&canonical, &mut HashSet::new()),
                );
            }
        }
    }

    if let Some(module_values) = index.module_value_types.get(module_name) {
        for (name, ty) in module_values {
            env.types.entry(name.clone()).or_insert_with(|| ty.clone());
        }
    }
    if let Some(module_aliases) = index.module_symbol_aliases.get(module_name) {
        for (name, path) in module_aliases {
            if index.function_path_exists(path) {
                env.callable_aliases.entry(name.clone()).or_insert_with(|| path.clone());
            }
        }
    }

    for (alias, path) in &imports.aliases {
        if let Some(ty) = index.module_value_type_by_path(path) {
            env.types.insert(alias.clone(), ty);
        } else {
            env.types.insert(alias.clone(), canonicalize_project_path(index, path));
        }
        // Imported module objects may be monkey patched at module execution
        // time.  Mirror their known members into the local object-field view so
        // `repo.run(...)` resolves to the patched callable.
        let canonical = canonicalize_project_path(index, path);
        if index.module_exists(&canonical) {
            if let Some(fields) = index.module_value_types.get(&canonical) {
                env.local_field_types
                    .entry(alias.clone())
                    .or_default()
                    .extend(fields.clone());
            }
        }
    }

    (env, infer_project_known_classes(index))
}

fn decorate_project_callable_type(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    base_callable_ty: &str,
) -> String {
    let mut current = canonicalize_project_path(index, base_callable_ty);
    for raw in func.decorators.iter().rev() {
        let normalized = normalize_py_decorator_name(raw);
        if matches!(
            normalized.as_str(),
            "staticmethod" | "classmethod" | "property"
        ) || normalized.ends_with(".setter")
            || normalized.ends_with(".deleter")
        {
            continue;
        }
        let target_expr = raw
            .trim()
            .strip_prefix('@')
            .map(|value| value.trim())
            .unwrap_or_else(|| raw.trim());
        let decorator_expr = if let Some((callee_text, _)) = parse_call_parts(target_expr) {
            callee_text
        } else {
            target_expr.to_string()
        };
        let Some(path) = infer_project_symbol_path(&decorator_expr, module_name, imports, index) else {
            continue;
        };
        let canonical = canonicalize_project_path(index, &path);
        if let Some(ret) = index.top_level_return(&canonical, 1) {
            current = canonicalize_project_path(index, &ret);
        }
    }
    current
}

fn project_callable_return_from_type(
    index: &PyProjectIndex,
    callable_ty: &str,
    arg_count: usize,
) -> Option<String> {
    if let Some(ret) = callable_ty.strip_prefix("callable<").and_then(|rest| rest.strip_suffix('>')) {
        return Some(ret.to_string());
    }
    let canonical = canonicalize_project_path(index, callable_ty);
    if index.function_path_exists(&canonical) {
        return index.top_level_return(&canonical, arg_count);
    }
    index.method_return(&canonical, "__call__", arg_count)
}

fn seed_project_inference_env_with_outer(
    func: &PyFunctionText,
    module_name: &str,
    imports: &PyImports,
    index: &PyProjectIndex,
    current_class: Option<&str>,
    current_class_bases: &[String],
    current_fields: &HashMap<String, String>,
    outer_env: Option<&PyEnv>,
) -> (PyEnv, HashSet<String>) {
    let (mut env, known_classes) = seed_project_inference_env(
        func,
        module_name,
        imports,
        index,
        current_class,
        current_class_bases,
        current_fields,
    );
    if let Some(outer) = outer_env {
        env.types.extend(outer.types.clone());
        env.callable_aliases.extend(outer.callable_aliases.clone());
        env.local_object_aliases.extend(outer.local_object_aliases.clone());
        env.executed_modules.extend(outer.executed_modules.clone());
        for (name, fields) in &outer.local_field_types {
            env.local_field_types
                .entry(name.clone())
                .or_default()
                .extend(fields.clone());
        }
        for (name, slots) in &outer.precise_index_types {
            env.precise_index_types
                .entry(name.clone())
                .or_default()
                .extend(slots.clone());
        }
        for (name, slots) in &outer.precise_index_callables {
            env.precise_index_callables
                .entry(name.clone())
                .or_default()
                .extend(slots.clone());
        }
        env.capturable_vars.extend(outer.capturable_vars.clone());
        env.capturable_vars.extend(outer.vars.clone());
    }
    (env, known_classes)
}


fn summary_find_nested_block_end(lines: &[PyBodyLine], start_idx: usize, header_indent: usize) -> usize {
    let mut idx = start_idx;
    while idx < lines.len() {
        let trimmed = lines[idx].text.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') && lines[idx].indent <= header_indent {
            break;
        }
        idx += 1;
    }
    idx
}

fn bind_project_summary_loop_target(
    target_text: &str,
    iterable_text: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let destructured_targets = parse_destructuring_targets(target_text.trim());
    let item_ty = infer_iterable_item_type(iterable_text, imports, env, known_classes);
    if destructured_targets.is_empty() {
        let name = target_text.trim();
        if is_simple_ident(name) {
            if let Some(ty) = item_ty.clone() {
                env.types.insert(name.to_string(), ty.clone());
                if let Some(path) = callable_path_from_type(&env.project_index, &ty) {
                    env.callable_aliases.insert(name.to_string(), path);
                } else {
                    env.callable_aliases.remove(name);
                }
            }
        }
        return;
    }
    if let Some(target_types) = item_ty.as_deref().and_then(destructure_type_elements) {
        for (target, ty) in destructured_targets.into_iter().zip(target_types.into_iter()) {
            env.types.insert(target.clone(), ty.clone());
            if let Some(path) = callable_path_from_type(&env.project_index, &ty) {
                env.callable_aliases.insert(target, path);
            }
        }
    }
}

fn apply_project_summary_with_alias_bindings(
    header_text: &str,
    imports: &PyImports,
    env: &mut PyEnv,
    known_classes: &HashSet<String>,
) {
    let inner = header_text
        .trim()
        .strip_prefix("async with ")
        .or_else(|| header_text.trim().strip_prefix("with "))
        .and_then(|rest| rest.strip_suffix(':'))
        .map(|rest| rest.trim().to_string())
        .unwrap_or_default();
    for item in split_top_level_commas(&inner).into_iter().filter(|part| !part.trim().is_empty()) {
        let Some((expr_text, alias_text)) = split_once_top_level_str(&item, " as ", false) else {
            continue;
        };
        let alias = alias_text.trim();
        if !is_simple_ident(alias) {
            continue;
        }
        let inferred_ty = context_manager_alias_type(&expr_text, imports, env, known_classes)
            .or_else(|| infer_simple_python_type(&expr_text, imports, env, known_classes));
        if let Some(ty) = inferred_ty {
            env.types.insert(alias.to_string(), ty);
        }
        if let Some(path) = infer_project_callable_value_type(&expr_text, imports, env, known_classes) {
            env.callable_aliases.insert(alias.to_string(), path);
        } else {
            env.callable_aliases.remove(alias);
        }
        env.local_object_aliases.remove(alias);
        env.local_field_types.remove(alias);
        populate_precise_container_slots_from_expr(env, alias, &expr_text, imports, known_classes);
    }
}

