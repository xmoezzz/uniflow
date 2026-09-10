const LEGACY_JAVA_TAINT: &str = include_str!("../../../../rules/legacy/java-taint.yml");
const LEGACY_JAVA_TAINT_SUPPLEMENT: &str =
    include_str!("../../../../rules/legacy/java-taint-supplement.yml");
const LEGACY_JAVASCRIPT_TAINT: &str = include_str!("../../../../rules/legacy/javascript-taint.yml");
const LEGACY_JAVASCRIPT_SEMGREP_TAINT: &str =
    include_str!("../../../../rules/legacy/javascript-semgrep-taint.yml");
const LEGACY_C_CPP_TAINT: &str = include_str!("../../../../rules/legacy/c-cpp-taint.yml");
const LEGACY_OBJC_OBJCPP_TAINT: &str =
    include_str!("../../../../rules/legacy/objc-objcpp-taint.yml");
const LEGACY_PYTHON_TAINT: &str = include_str!("../../../../rules/legacy/python-taint.yml");
const LEGACY_GO_TAINT: &str = include_str!("../../../../rules/legacy/go-taint.yml");
const LEGACY_CSHARP_TAINT: &str = include_str!("../../../../rules/legacy/csharp-taint.yml");
const LEGACY_RUBY_SEMGREP_TAINT: &str =
    include_str!("../../../../rules/legacy/ruby-semgrep-taint.yml");

static LEGACY_JAVA_RULES: OnceLock<RuleSet> = OnceLock::new();
static LEGACY_JAVASCRIPT_RULES: OnceLock<RuleSet> = OnceLock::new();
static LEGACY_C_CPP_RULES: OnceLock<RuleSet> = OnceLock::new();
static LEGACY_OBJC_OBJCPP_RULES: OnceLock<RuleSet> = OnceLock::new();
static LEGACY_PYTHON_RULES: OnceLock<RuleSet> = OnceLock::new();
static LEGACY_GO_RULES: OnceLock<RuleSet> = OnceLock::new();
static LEGACY_CSHARP_RULES: OnceLock<RuleSet> = OnceLock::new();
static LEGACY_RUBY_RULES: OnceLock<RuleSet> = OnceLock::new();

pub fn legacy_models_for(language: Language) -> Result<RuleSet> {
    let rules = match language {
        Language::Cpp => parsed_legacy_c_cpp()?.clone(),
        Language::C => retarget_models(parsed_legacy_c_cpp()?.clone(), language),
        Language::ObjC => parsed_legacy_objc_objcpp()?.clone(),
        Language::ObjCpp => retarget_models(parsed_legacy_objc_objcpp()?.clone(), language),
        Language::Java => parsed_legacy_java()?.clone(),
        Language::Kotlin | Language::Jsp => {
            retarget_models(parsed_legacy_java()?.clone(), language)
        }
        Language::JavaScript => parsed_legacy_javascript()?.clone(),
        Language::Python => parsed_legacy_python()?.clone(),
        Language::Go => parsed_legacy_go()?.clone(),
        Language::CSharp => parsed_legacy_csharp()?.clone(),
        Language::Ruby => parsed_legacy_ruby()?.clone(),
        _ => RuleSet::default(),
    };
    rules.validate()?;
    Ok(rules)
}

fn parsed_legacy_c_cpp() -> Result<&'static RuleSet> {
    if let Some(rules) = LEGACY_C_CPP_RULES.get() {
        return Ok(rules);
    }
    let parsed = RuleSet::from_yaml_str(LEGACY_C_CPP_TAINT)?;
    let _ = LEGACY_C_CPP_RULES.set(parsed);
    Ok(LEGACY_C_CPP_RULES
        .get()
        .expect("legacy C/C++ rules initialized"))
}

fn parsed_legacy_objc_objcpp() -> Result<&'static RuleSet> {
    if let Some(rules) = LEGACY_OBJC_OBJCPP_RULES.get() {
        return Ok(rules);
    }
    let parsed = RuleSet::from_yaml_str(LEGACY_OBJC_OBJCPP_TAINT)?;
    let _ = LEGACY_OBJC_OBJCPP_RULES.set(parsed);
    Ok(LEGACY_OBJC_OBJCPP_RULES
        .get()
        .expect("legacy Objective-C rules initialized"))
}

fn parsed_legacy_java() -> Result<&'static RuleSet> {
    if let Some(rules) = LEGACY_JAVA_RULES.get() {
        return Ok(rules);
    }
    let mut parsed = RuleSet::from_yaml_str(LEGACY_JAVA_TAINT)?;
    parsed.merge(RuleSet::from_yaml_str(LEGACY_JAVA_TAINT_SUPPLEMENT)?);
    attach_general_java_sanitization_policy(&mut parsed);
    parsed.validate()?;
    let _ = LEGACY_JAVA_RULES.set(parsed);
    Ok(LEGACY_JAVA_RULES
        .get()
        .expect("legacy Java rules initialized"))
}

fn attach_general_java_sanitization_policy(rules: &mut RuleSet) {
    const POLICY_STANDARDS: [&str; 3] = [
        "cert:02000010140200",
        "legacy-product:0202000010140200",
        "legacy-product:0302000010140200",
    ];
    for metadata in &mut rules.metadata {
        if !metadata
            .cwe
            .iter()
            .any(|cwe| matches!(cwe.as_str(), "CWE-89" | "CWE-112" | "CWE-116" | "CWE-611"))
        {
            continue;
        }
        for standard in POLICY_STANDARDS {
            if !metadata.standards.iter().any(|value| value == standard) {
                metadata.standards.push(standard.to_string());
            }
        }
    }
}

fn parsed_legacy_javascript() -> Result<&'static RuleSet> {
    if let Some(rules) = LEGACY_JAVASCRIPT_RULES.get() {
        return Ok(rules);
    }
    let mut parsed = RuleSet::from_yaml_str(LEGACY_JAVASCRIPT_TAINT)?;
    parsed.merge(RuleSet::from_yaml_str(LEGACY_JAVASCRIPT_SEMGREP_TAINT)?);
    parsed.validate()?;
    let _ = LEGACY_JAVASCRIPT_RULES.set(parsed);
    Ok(LEGACY_JAVASCRIPT_RULES
        .get()
        .expect("legacy JavaScript rules initialized"))
}

fn parsed_legacy_python() -> Result<&'static RuleSet> {
    if let Some(rules) = LEGACY_PYTHON_RULES.get() {
        return Ok(rules);
    }
    let parsed = RuleSet::from_yaml_str(LEGACY_PYTHON_TAINT)?;
    let _ = LEGACY_PYTHON_RULES.set(parsed);
    Ok(LEGACY_PYTHON_RULES
        .get()
        .expect("legacy Python rules initialized"))
}

fn parsed_legacy_go() -> Result<&'static RuleSet> {
    if let Some(rules) = LEGACY_GO_RULES.get() {
        return Ok(rules);
    }
    let parsed = RuleSet::from_yaml_str(LEGACY_GO_TAINT)?;
    let _ = LEGACY_GO_RULES.set(parsed);
    Ok(LEGACY_GO_RULES.get().expect("legacy Go rules initialized"))
}

fn parsed_legacy_csharp() -> Result<&'static RuleSet> {
    if let Some(rules) = LEGACY_CSHARP_RULES.get() {
        return Ok(rules);
    }
    let parsed = RuleSet::from_yaml_str(LEGACY_CSHARP_TAINT)?;
    let _ = LEGACY_CSHARP_RULES.set(parsed);
    Ok(LEGACY_CSHARP_RULES
        .get()
        .expect("legacy C# rules initialized"))
}

fn parsed_legacy_ruby() -> Result<&'static RuleSet> {
    if let Some(rules) = LEGACY_RUBY_RULES.get() {
        return Ok(rules);
    }
    let parsed = RuleSet::from_yaml_str(LEGACY_RUBY_SEMGREP_TAINT)?;
    let _ = LEGACY_RUBY_RULES.set(parsed);
    Ok(LEGACY_RUBY_RULES
        .get()
        .expect("legacy Ruby rules initialized"))
}
