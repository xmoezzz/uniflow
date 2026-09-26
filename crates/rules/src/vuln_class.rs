//! One table of weakness classes shared by every rule pack and every stage
//! that needs to say *what kind* of weakness a finding is: the legacy pack
//! compilers (Go / Python / C/C++ categories carry only a vendor category
//! name like `sast_sql_injection` or `safeCommandInjection`), the MIT and
//! built-in models (only a sink `kind` such as `sql`), the rule-catalog
//! export, and the taint engine's finding builder as a last resort.
//!
//! Before this existed each consumer either had its own partial mapping or
//! none: a Go SQL-injection finding reached Cosmos titled "Go security rule
//! 15000010060001" with no CWE, so it could not be scored, grouped by CWE /
//! OWASP, or placed in any standards book.
//!
//! The mapping is deliberately conservative. A category that does not name
//! a weakness (`generic`, `taint`, a transport such as `network`) maps to
//! nothing — an invented CWE is worse than none.

/// A weakness class: its primary CWE and display text in the three UI
/// languages Cosmos ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VulnClass {
    pub cwe: u32,
    pub cwe_name: &'static str,
    pub en: &'static str,
    pub zh_cn: &'static str,
    pub zh_tw: &'static str,
}

impl VulnClass {
    pub fn cwe_id(&self) -> String {
        format!("CWE-{}", self.cwe)
    }

    /// The `"CWE:<n>:<name>"` standards tag the rule catalog indexes.
    pub fn cwe_standard(&self) -> String {
        format!("CWE:{}:{}", self.cwe, self.cwe_name)
    }
}

macro_rules! class {
    ($cwe:expr, $name:expr, $en:expr, $zh_cn:expr, $zh_tw:expr) => {
        VulnClass { cwe: $cwe, cwe_name: $name, en: $en, zh_cn: $zh_cn, zh_tw: $zh_tw }
    };
}

pub const SQL_INJECTION: VulnClass = class!(89, "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "SQL injection", "SQL 注入", "SQL 注入");
pub const COMMAND_INJECTION: VulnClass = class!(78, "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')", "OS command injection", "命令注入", "命令注入");
pub const PATH_TRAVERSAL: VulnClass = class!(22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "Path traversal", "路径遍历", "路徑遍歷");
pub const XSS: VulnClass = class!(79, "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "Cross-site scripting", "跨站脚本", "跨站腳本");
pub const SSRF: VulnClass = class!(918, "Server-Side Request Forgery (SSRF)", "Server-side request forgery", "服务端请求伪造", "伺服器端請求偽造");
pub const CODE_INJECTION: VulnClass = class!(94, "Improper Control of Generation of Code ('Code Injection')", "Code injection", "代码注入", "程式碼注入");
pub const DESERIALIZATION: VulnClass = class!(502, "Deserialization of Untrusted Data", "Unsafe deserialization", "不安全反序列化", "不安全反序列化");
pub const FORMAT_STRING: VulnClass = class!(134, "Use of Externally-Controlled Format String", "Format string injection", "格式化字符串注入", "格式化字串注入");
pub const LOG_INJECTION: VulnClass = class!(117, "Improper Output Neutralization for Logs", "Log injection", "日志注入", "日誌注入");
pub const XXE: VulnClass = class!(611, "Improper Restriction of XML External Entity Reference", "XML external entity", "XML 外部实体", "XML 外部實體");
pub const XML_INJECTION: VulnClass = class!(91, "XML Injection (aka Blind XPath Injection)", "XML injection", "XML 注入", "XML 注入");
pub const OPEN_REDIRECT: VulnClass = class!(601, "URL Redirection to Untrusted Site ('Open Redirect')", "Open redirect", "开放重定向", "開放重新導向");
pub const LDAP_INJECTION: VulnClass = class!(90, "Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')", "LDAP injection", "LDAP 注入", "LDAP 注入");
pub const XPATH_INJECTION: VulnClass = class!(643, "Improper Neutralization of Data within XPath Expressions ('XPath Injection')", "XPath injection", "XPath 注入", "XPath 注入");
pub const TEMPLATE_INJECTION: VulnClass = class!(1336, "Improper Neutralization of Special Elements Used in a Template Engine", "Template injection", "模板注入", "模板注入");
pub const REDOS: VulnClass = class!(1333, "Inefficient Regular Expression Complexity", "Regular expression denial of service", "正则表达式拒绝服务", "正規表示式阻斷服務");
pub const INJECTION: VulnClass = class!(74, "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')", "Injection", "注入", "注入");
pub const WEAK_CRYPTO: VulnClass = class!(327, "Use of a Broken or Risky Cryptographic Algorithm", "Weak cryptographic algorithm", "弱加密算法", "弱加密演算法");
pub const WEAK_HASH: VulnClass = class!(328, "Use of Weak Hash", "Weak hash", "弱哈希算法", "弱雜湊演算法");
pub const WEAK_RANDOM: VulnClass = class!(330, "Use of Insufficiently Random Values", "Insecure randomness", "不安全的随机数", "不安全的亂數");
pub const HEADER_INJECTION: VulnClass = class!(113, "Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')", "HTTP header injection", "HTTP 头注入", "HTTP 標頭注入");
pub const RESOURCE_INJECTION: VulnClass = class!(99, "Improper Control of Resource Identifiers ('Resource Injection')", "Resource injection", "资源注入", "資源注入");
pub const SETTING_MANIPULATION: VulnClass = class!(15, "External Control of System or Configuration Setting", "Setting manipulation", "配置篡改", "設定竄改");
pub const PRIVACY_VIOLATION: VulnClass = class!(359, "Exposure of Private Personal Information to an Unauthorized Actor", "Privacy violation", "隐私泄露", "隱私洩漏");
pub const INFO_LEAK: VulnClass = class!(497, "Exposure of Sensitive System Information to an Unauthorized Control Sphere", "System information leak", "系统信息泄露", "系統資訊洩漏");
pub const ACCESS_CONTROL_DB: VulnClass = class!(566, "Authorization Bypass Through User-Controlled SQL Primary Key", "Database access control bypass", "数据库访问控制绕过", "資料庫存取控制繞過");
pub const FILE_PERMISSION: VulnClass = class!(732, "Incorrect Permission Assignment for Critical Resource", "File permission manipulation", "文件权限篡改", "檔案權限竄改");
pub const DENIAL_OF_SERVICE: VulnClass = class!(400, "Uncontrolled Resource Consumption", "Denial of service", "拒绝服务", "阻斷服務");
pub const TRUST_BOUNDARY: VulnClass = class!(501, "Trust Boundary Violation", "Trust boundary violation", "信任边界违规", "信任邊界違規");
pub const INSECURE_COOKIE: VulnClass = class!(614, "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", "Cookie without Secure flag", "Cookie 未设置 Secure 标志", "Cookie 未設定 Secure 旗標");
pub const PLAINTEXT_PASSWORD: VulnClass = class!(256, "Plaintext Storage of a Password", "Password management", "口令管理不当", "密碼管理不當");
pub const FORMULA_INJECTION: VulnClass = class!(1236, "Improper Neutralization of Formula Elements in a CSV File", "Formula injection", "公式注入", "公式注入");
pub const BUFFER_OVERFLOW: VulnClass = class!(120, "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')", "Buffer overflow", "缓冲区溢出", "緩衝區溢位");
pub const INTEGER_OVERFLOW: VulnClass = class!(190, "Integer Overflow or Wraparound", "Integer overflow", "整数溢出", "整數溢位");
pub const USE_AFTER_FREE: VulnClass = class!(416, "Use After Free", "Use after free", "释放后使用", "釋放後使用");
pub const DOUBLE_FREE: VulnClass = class!(415, "Double Free", "Double free", "重复释放", "重複釋放");
pub const NULL_DEREFERENCE: VulnClass = class!(476, "NULL Pointer Dereference", "NULL pointer dereference", "空指针解引用", "空指標解參考");
pub const MEMORY_LEAK: VulnClass = class!(401, "Missing Release of Memory after Effective Lifetime", "Memory leak", "内存泄漏", "記憶體洩漏");
pub const HARDCODED_CREDENTIALS: VulnClass = class!(798, "Use of Hard-coded Credentials", "Hard-coded credentials", "硬编码凭据", "硬編碼憑證");
pub const CREDENTIAL_EXPOSURE: VulnClass = class!(522, "Insufficiently Protected Credentials", "Credential exposure", "凭据保护不足", "憑證保護不足");
pub const EMAIL_INJECTION: VulnClass = class!(93, "Improper Neutralization of CRLF Sequences ('CRLF Injection')", "Email/CRLF injection", "CRLF 注入", "CRLF 注入");
pub const CERT_VALIDATION: VulnClass = class!(295, "Improper Certificate Validation", "Improper certificate validation", "证书校验不当", "憑證驗證不當");

/// The class a taint *sink kind* names (the MIT and built-in models'
/// vocabulary: `sql`, `command`, `path`, …). Kinds that describe a
/// transport or a source rather than a weakness map to `None`.
pub fn for_sink_kind(kind: &str) -> Option<VulnClass> {
    Some(match kind.to_ascii_lowercase().as_str() {
        "sql" | "sqli" | "database" => SQL_INJECTION,
        "command" | "cmd" | "shell" | "exec" => COMMAND_INJECTION,
        "path" | "path_traversal" | "filesystem" => PATH_TRAVERSAL,
        "xss" | "html" => XSS,
        "ssrf" | "http" => SSRF,
        "code" | "eval" | "code_injection" => CODE_INJECTION,
        "deserialization" | "unsafe_deserialization" => DESERIALIZATION,
        "format" | "format_string" => FORMAT_STRING,
        "log" | "logging" => LOG_INJECTION,
        "xml" | "xxe" => XXE,
        "redirect" | "open_redirect" => OPEN_REDIRECT,
        "ldap" => LDAP_INJECTION,
        "xpath" => XPATH_INJECTION,
        "template" | "ssti" => TEMPLATE_INJECTION,
        "regex" | "redos" => REDOS,
        "jndi" => INJECTION,
        "crypto" | "weak_crypto" => WEAK_CRYPTO,
        "hash" | "weak_hash" => WEAK_HASH,
        "random" | "weak_random" => WEAK_RANDOM,
        "header" | "crlf" => HEADER_INJECTION,
        "trust_boundary" => TRUST_BOUNDARY,
        // Pysa taint-sink kinds (the legacy Python pack's only
        // classification): https://pyre-check.org/docs/pysa-basics
        "remotecodeexecution" => CODE_INJECTION,
        "execenvsink" | "viatypeof[args]" => COMMAND_INJECTION,
        "filesystem_readwrite" | "filesystem_other" => PATH_TRAVERSAL,
        "requestsend_uri" | "requestsend_data" | "requestsend_metadata" => SSRF,
        "returnedtouser" => XSS,
        "responseheadername" | "responseheadervalue" => HEADER_INJECTION,
        "xmlparser" => XXE,
        "authentication" => CREDENTIAL_EXPOSURE,
        "emailsend" => EMAIL_INJECTION,
        _ => return None,
    })
}

/// Lower-cased words of a vendor category name, whatever its spelling:
/// `safeSqlInjection`, `sast_sql_injection`, `Security.Dataflow.CppCommandInjected`
/// and `SQL-injection` all become `… sql injection …`.
fn words(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    let mut previous: Option<char> = None;
    for c in text.chars() {
        if c.is_ascii_alphanumeric() {
            let boundary = matches!(previous, Some(p) if (p.is_ascii_lowercase() || p.is_ascii_digit()) && c.is_ascii_uppercase());
            if boundary {
                out.push(' ');
            }
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with(' ') {
            out.push(' ');
        }
        previous = Some(c);
    }
    format!(" {} ", out.trim())
}

/// (needles, class), most specific first: the first class any of whose
/// needles occurs in the normalized words wins, so "header manipulation
/// cookies" is decided before a later, broader "injection" needle could be.
const CATEGORY_NEEDLES: &[(&[&str], VulnClass)] = &[
    (&[" access control database"], ACCESS_CONTROL_DB),
    (&[" sql injection", " sqli ", " sql inject", " hql ", " nosql injection"], SQL_INJECTION),
    (&[" command inject", " os command", " command execution", " exec arg", " process injection", " shell inject"], COMMAND_INJECTION),
    (&[" ldap"], LDAP_INJECTION),
    (&[" xpath"], XPATH_INJECTION),
    (&[" xml external", " xxe", " external entit"], XXE),
    (&[" xml injection"], XML_INJECTION),
    (&[" cross site scripting", " xss", " html injection"], XSS),
    (&[" open redirect", " url redirect", " unvalidated redirect"], OPEN_REDIRECT),
    (&[" server side request forgery", " ssrf", " request forgery"], SSRF),
    (&[" header manipulation", " response splitting", " crlf", " http header"], HEADER_INJECTION),
    (&[" log forging", " log injection", " log forge"], LOG_INJECTION),
    (&[" dynamic code evaluation", " code injection", " code inject", " eval injection", " script injection"], CODE_INJECTION),
    (&[" template injection", " ssti"], TEMPLATE_INJECTION),
    (&[" deserializ"], DESERIALIZATION),
    (&[" format string", " format injection", " uncontrolled format"], FORMAT_STRING),
    (&[" path manipulation", " path traversal", " directory traversal", " zip entry", " zip slip", " file inclusion", " path inject"], PATH_TRAVERSAL),
    (&[" regular expression", " redos", " regex injection"], REDOS),
    (&[" resource injection", " connection string", " parameter pollution"], RESOURCE_INJECTION),
    (&[" setting manipulation"], SETTING_MANIPULATION),
    (&[" privacy violation"], PRIVACY_VIOLATION),
    (&[" system information leak", " information leak", " information exposure"], INFO_LEAK),
    (&[" file permission"], FILE_PERMISSION),
    (&[" insecure random", " weak random", " predictable random"], WEAK_RANDOM),
    (&[" weak hash", " broken hash"], WEAK_HASH),
    (&[" weak encryption", " weak cryptograph", " broken crypto", " risky crypto"], WEAK_CRYPTO),
    (&[" trust boundary"], TRUST_BOUNDARY),
    (&[" formula injection", " csv injection"], FORMULA_INJECTION),
    (&[" password management"], PLAINTEXT_PASSWORD),
    (&[" hardcoded", " hard coded", " hard-coded"], HARDCODED_CREDENTIALS),
    (&[" certificate validation", " insecure tls", " insecure ssl"], CERT_VALIDATION),
    (&[" buffer overflow", " buffer overrun", " out of bounds write", " stack overflow", " heap overflow"], BUFFER_OVERFLOW),
    (&[" integer overflow", " integer wrap"], INTEGER_OVERFLOW),
    (&[" use after free"], USE_AFTER_FREE),
    (&[" double free"], DOUBLE_FREE),
    (&[" null pointer", " null dereference", " null deref"], NULL_DEREFERENCE),
    (&[" memory leak"], MEMORY_LEAK),
    (&[" denial of service"], DENIAL_OF_SERVICE),
    (&[" json injection", " injection"], INJECTION),
];

/// The class a vendor category name / legacy "safe" sign describes, e.g.
/// `safeSqlInjection` → SQL injection, `sast_command_injection` → OS
/// command injection, `CppFormatString` → format string. `None` when the
/// text names no weakness this table knows.
pub fn classify_category(text: &str) -> Option<VulnClass> {
    let normalized = words(text);
    CATEGORY_NEEDLES
        .iter()
        .find(|(needles, _)| needles.iter().any(|needle| normalized.contains(needle)))
        .map(|(_, class)| *class)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vendor_category_spellings_classify_to_their_weakness() {
        assert_eq!(classify_category("safeSqlInjection"), Some(SQL_INJECTION));
        assert_eq!(classify_category("sast_sql_injection"), Some(SQL_INJECTION));
        assert_eq!(classify_category("Security.Dataflow.CppCommandInjected"), Some(COMMAND_INJECTION));
        assert_eq!(classify_category("safeHeaderManipulationCookies"), Some(HEADER_INJECTION));
        assert_eq!(classify_category("safeCrossSiteScriptingReflected"), Some(XSS));
        assert_eq!(classify_category("safePathManipulationZipEntryOverwrite"), Some(PATH_TRAVERSAL));
        assert_eq!(classify_category("safeDynamicCodeEvaluationCodeInjection"), Some(CODE_INJECTION));
        assert_eq!(classify_category("safeDenialOfServiceRegularExpression"), Some(REDOS));
        assert_eq!(classify_category("safeServerSideRequestForgery"), Some(SSRF));
    }

    #[test]
    fn categories_that_name_no_weakness_stay_unclassified() {
        for text in ["generic", "taint", "network", "UserControlled", "Go security rule 15000010060001"] {
            assert_eq!(classify_category(text), None, "{text}");
        }
        assert_eq!(for_sink_kind("generic"), None);
        assert_eq!(for_sink_kind("network"), None);
    }

    #[test]
    fn sink_kinds_map_to_their_weakness() {
        assert_eq!(for_sink_kind("sql").map(|c| c.cwe), Some(89));
        assert_eq!(for_sink_kind("Command").map(|c| c.cwe), Some(78));
        assert_eq!(for_sink_kind("crypto").map(|c| c.cwe), Some(327));
    }
}
