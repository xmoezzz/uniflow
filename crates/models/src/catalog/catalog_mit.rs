/// (CWE number, CWE name, English sink description, Simplified Chinese,
/// Traditional Chinese) for each MIT taint-sink `kind`. The MIT-derived
/// models (Pysa, Mariana Trench, Infer, CodeQL) carry only an id, a matcher
/// and a `kind` — no title, CWE or standards — so without this they would
/// show up in the rule catalog as bare ids with no place in any standard.
/// Kinds that are sources/transport rather than a weakness (`user_input`,
/// `environment`, `network`, `android`, `url`, `file`) intentionally map to
/// `None`: tagging those sinks with an invented CWE would be worse than
/// leaving them out of the standards books.
fn mit_sink_kind_classification(kind: &str) -> Option<(u32, &'static str, &'static str, &'static str, &'static str)> {
    Some(match kind {
        "sql" => (89, "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "SQL injection sink", "SQL 注入汇聚点", "SQL 注入匯聚點"),
        "command" => (78, "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", "OS command injection sink", "命令注入汇聚点", "命令注入匯聚點"),
        "path" => (22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "Path traversal sink", "路径遍历汇聚点", "路徑遍歷匯聚點"),
        "xss" => (79, "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "Cross-site scripting sink", "跨站脚本汇聚点", "跨站腳本匯聚點"),
        "ssrf" | "http" => (918, "Server-Side Request Forgery (SSRF)", "Server-side request forgery sink", "服务端请求伪造汇聚点", "伺服器端請求偽造匯聚點"),
        "code" => (94, "Improper Control of Generation of Code ('Code Injection')", "Code injection sink", "代码注入汇聚点", "程式碼注入匯聚點"),
        "deserialization" => (502, "Deserialization of Untrusted Data", "Unsafe deserialization sink", "不安全反序列化汇聚点", "不安全反序列化匯聚點"),
        "format" => (134, "Use of Externally-Controlled Format String", "Format string sink", "格式化字符串汇聚点", "格式化字串匯聚點"),
        "log" => (117, "Improper Output Neutralization for Logs", "Log injection sink", "日志注入汇聚点", "日誌注入匯聚點"),
        "xml" => (611, "Improper Restriction of XML External Entity Reference", "XML external entity sink", "XML 外部实体汇聚点", "XML 外部實體匯聚點"),
        "redirect" => (601, "URL Redirection to Untrusted Site ('Open Redirect')", "Open redirect sink", "开放重定向汇聚点", "開放重新導向匯聚點"),
        "ldap" => (90, "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')", "LDAP injection sink", "LDAP 注入汇聚点", "LDAP 注入匯聚點"),
        "xpath" => (643, "Improper Neutralization of Data within XPath Expressions ('XPath Injection')", "XPath injection sink", "XPath 注入汇聚点", "XPath 注入匯聚點"),
        "template" => (1336, "Improper Neutralization of Special Elements Used in a Template Engine", "Template injection sink", "模板注入汇聚点", "模板注入匯聚點"),
        "regex" => (1333, "Inefficient Regular Expression Complexity", "Regular expression injection sink", "正则表达式注入汇聚点", "正規表示式注入匯聚點"),
        "jndi" => (74, "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "JNDI injection sink", "JNDI 注入汇聚点", "JNDI 注入匯聚點"),
        "crypto" => (327, "Use of a Broken or Risky Cryptographic Algorithm", "Weak cryptography sink", "弱加密算法汇聚点", "弱加密演算法匯聚點"),
        _ => return None,
    })
}

fn mit_pack_name(rule_id: &str) -> &'static str {
    if rule_id.starts_with("mit-pysa") {
        "Pysa"
    } else if rule_id.starts_with("mit-mariana") {
        "Mariana Trench"
    } else if rule_id.starts_with("mit-infer") {
        "Infer"
    } else {
        "CodeQL"
    }
}

/// Catalog metadata synthesized for every MIT-derived taint sink that maps
/// to a real weakness class (see [`mit_sink_kind_classification`]), one
/// entry per (sink, language) — the rule catalog bundle's MIT section.
pub fn mit_sink_rule_metadata() -> Result<Vec<CatalogedRule>> {
    const LANGUAGES: &[Language] = &[Language::Python, Language::Java, Language::Cpp];
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for language in LANGUAGES {
        let rules = mit_models_for(language.clone())?;
        for sink in rules.sinks {
            let Some((cwe, cwe_name, en, zh_cn, zh_tw)) = mit_sink_kind_classification(&sink.kind) else {
                continue;
            };
            let sink_language = sink.language.clone().unwrap_or_else(|| language.clone());
            if !seen.insert((sink.id.clone(), sink_language.as_str())) {
                continue;
            }
            let api = sink
                .matcher
                .exact
                .clone()
                .or_else(|| sink.matcher.contains.clone())
                .or_else(|| sink.matcher.regex.clone())
                .unwrap_or_else(|| sink.id.clone());
            let pack = mit_pack_name(&sink.id);
            let message = format!(
                "Calls to `{api}` are modeled as a taint sink ({en}, from the MIT-licensed {pack} models): untrusted data reaching them is reported as CWE-{cwe}."
            );
            let text = |title: String, message: String| Some(LocalizedRuleText { title, message });
            out.push(CatalogedRule {
                language: sink_language.as_str().to_string(),
                languages: Vec::new(),
                pack: "mit".to_string(),
                metadata: RuleMetadata {
                    id: sink.id.clone(),
                    title: format!("{en}: {api}"),
                    message: message.clone(),
                    severity: if matches!(sink.kind.as_str(), "command" | "sql" | "code" | "deserialization") {
                        "error".to_string()
                    } else {
                        "warning".to_string()
                    },
                    cwe: vec![format!("CWE-{cwe}")],
                    standards: vec![format!("CWE:{cwe}:{cwe_name}")],
                    categories: Default::default(),
                    translations: RuleTranslations {
                        zh_cn: text(format!("{zh_cn}：{api}"), format!("对 `{api}` 的调用被建模为污点汇聚点（{zh_cn}，来自 MIT 许可的 {pack} 模型）：不可信数据到达此处将报告为 CWE-{cwe}。")),
                        en: text(format!("{en}: {api}"), message),
                        zh_tw: text(format!("{zh_tw}：{api}"), format!("對 `{api}` 的呼叫被建模為汙點匯聚點（{zh_tw}，來自 MIT 授權的 {pack} 模型）：不可信資料到達此處將回報為 CWE-{cwe}。")),
                    },
                },
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod catalog_mit_tests {
    use super::*;

    #[test]
    fn mit_sinks_get_cwe_standards_and_translations() {
        let rules = mit_sink_rule_metadata().expect("mit catalog");
        assert!(rules.len() > 50, "expected most MIT sinks to classify, got {}", rules.len());
        let os_system = rules.iter().find(|rule| rule.metadata.id == "mit-pysa-py-sink-os-system").expect("os.system sink");
        assert_eq!(os_system.language, "python");
        assert_eq!(os_system.pack, "mit");
        assert_eq!(os_system.metadata.cwe, vec!["CWE-78".to_string()]);
        assert!(os_system.metadata.standards[0].starts_with("CWE:78:"));
        assert!(os_system.metadata.translations.zh_cn.as_ref().unwrap().title.contains("os.system"));
        // Source/transport kinds must not be invented into a weakness class.
        assert!(mit_sink_kind_classification("user_input").is_none());
    }
}
