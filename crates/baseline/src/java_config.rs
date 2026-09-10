use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use uniflow_parser_core::java_syntax::{JavaDeclarationKind as D, JavaSyntax};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JavaProjectCheck {
    Struts2ActionFieldWithoutValidator,
    Struts2DuplicateValidationFiles,
    Struts2UndeclaredValidator,
    Struts2UnvalidatedAction,
    Struts2ValidationFileWithoutAction,
    Struts2ValidatorWithoutActionField,
    StrutsDuplicateValidationForms,
    StrutsErroneousValidateMethod,
    StrutsFormDoesNotExtendValidationClass,
    StrutsFormFieldWithoutValidator,
    StrutsUnusedValidationForm,
    StrutsUnvalidatedActionForm,
    StrutsValidatorWithoutFormField,
}

impl JavaProjectCheck {
    pub(crate) fn offsets(self, sources: &HashMap<String, String>) -> Vec<(String, usize)> {
        let project = StrutsProject::new(sources);
        project.offsets(self)
    }
}

#[derive(Default)]
struct StrutsProject {
    classes: HashMap<String, ProjectClass>,
    validation_files: Vec<ValidationFile>,
    forms: HashMap<String, (String, usize, String)>,
    actions: Vec<(String, String, bool, usize, String)>,
}

#[derive(Default)]
struct ProjectClass {
    path: String,
    offset: usize,
    superclass: String,
    fields: Vec<(String, usize)>,
    bad_validate: Vec<usize>,
}

struct ValidationFile {
    path: String,
    action: String,
    offset: usize,
    fields: Vec<(String, usize)>,
    validator_types: Vec<(String, usize)>,
    form_names: Vec<(String, usize)>,
}

impl StrutsProject {
    fn new(sources: &HashMap<String, String>) -> Self {
        let mut project = Self::default();
        for (path, source) in sources {
            if path.ends_with(".java") {
                let syntax = JavaSyntax::parse(source);
                for (id, class) in syntax.declarations.iter().enumerate().filter(|(_, item)| {
                    matches!(item.kind, D::Class | D::Record)
                }) {
                    let mut value = ProjectClass {
                        path: path.clone(),
                        offset: class.range.start,
                        superclass: class.superclass.clone(),
                        ..Default::default()
                    };
                    for member in syntax.declarations.iter().filter(|item| item.owner == Some(id)) {
                        if member.kind == D::Field {
                            value.fields.extend(
                                member
                                    .names
                                    .iter()
                                    .cloned()
                                    .map(|name| (name, member.range.start)),
                            );
                        } else if member.kind == D::Method && member.name == "validate" {
                            let parameter_types = member
                                .parameters
                                .clone()
                                .map(|range| {
                                    syntax
                                        .tokens_in(range)
                                        .filter(|token| token.text.ends_with("ActionMapping")
                                            || token.text.ends_with("HttpServletRequest"))
                                        .count()
                                })
                                .unwrap_or(0);
                            if member.declared_type.rsplit('.').next() != Some("ActionErrors")
                                || parameter_types < 2
                            {
                                value.bad_validate.push(member.range.start);
                            }
                        }
                    }
                    project.classes.insert(class.name.clone(), value);
                }
                continue;
            }
            if !path.ends_with(".xml") || sxd_document::parser::parse(source).is_err() {
                continue;
            }
            let tags = start_tags(source);
            if path.ends_with("struts-config.xml") {
                for tag in &tags {
                    if tag.name == "form-bean" {
                        if let (Some(name), Some(ty)) = (tag.attribute("name"), tag.attribute("type")) {
                            project.forms.insert(
                                name.to_string(),
                                (ty.rsplit('.').next().unwrap_or(ty).to_string(), tag.offset, path.clone()),
                            );
                        }
                    } else if tag.name == "action" {
                        project.actions.push((
                            tag.attribute("name").unwrap_or_default().to_string(),
                            tag.attribute("type")
                                .and_then(|ty| ty.rsplit('.').next())
                                .unwrap_or_default()
                                .to_string(),
                            tag.attribute("validate") != Some("false"),
                            tag.offset,
                            path.clone(),
                        ));
                    }
                }
            }
            if path.ends_with("-validation.xml") || path.ends_with("validation.xml") {
                let file = path.rsplit('/').next().unwrap_or(path);
                let action = file
                    .strip_suffix("-validation.xml")
                    .unwrap_or_default()
                    .split('-')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                project.validation_files.push(ValidationFile {
                    path: path.clone(),
                    action,
                    offset: tags.first().map_or(0, |tag| tag.offset),
                    fields: tags
                        .iter()
                        .filter(|tag| tag.name == "field")
                        .filter_map(|tag| {
                            tag.attribute("name")
                                .or_else(|| tag.attribute("property"))
                                .map(|name| (name.to_string(), tag.offset))
                        })
                        .collect(),
                    validator_types: tags
                        .iter()
                        .filter(|tag| matches!(tag.name.as_str(), "field-validator" | "validator"))
                        .filter_map(|tag| tag.attribute("type").map(|ty| (ty.to_string(), tag.offset)))
                        .collect(),
                    form_names: tags
                        .iter()
                        .filter(|tag| tag.name == "form")
                        .filter_map(|tag| tag.attribute("name").map(|name| (name.to_string(), tag.offset)))
                        .collect(),
                });
            }
        }
        project
    }

    fn offsets(&self, check: JavaProjectCheck) -> Vec<(String, usize)> {
        use JavaProjectCheck as C;
        let mut findings = Vec::new();
        let builtins = [
            "required", "requiredstring", "stringlength", "int", "long", "double",
            "email", "url", "regex", "expression", "date", "conversion", "visitor",
        ];
        match check {
            C::Struts2DuplicateValidationFiles => {
                let mut seen = HashSet::new();
                for file in &self.validation_files {
                    if !file.action.is_empty() && !seen.insert(file.action.clone()) {
                        findings.push((file.path.clone(), file.offset));
                    }
                }
            }
            C::Struts2ValidationFileWithoutAction => {
                for file in &self.validation_files {
                    if !file.action.is_empty() && !self.classes.contains_key(&file.action) {
                        findings.push((file.path.clone(), file.offset));
                    }
                }
            }
            C::Struts2UnvalidatedAction => {
                for (name, class) in &self.classes {
                    let action = name.ends_with("Action")
                        || class.superclass.rsplit('.').next() == Some("ActionSupport");
                    if action && !self.validation_files.iter().any(|file| file.action == *name) {
                        findings.push((class.path.clone(), class.offset));
                    }
                }
            }
            C::Struts2ActionFieldWithoutValidator => {
                for file in &self.validation_files {
                    if let Some(class) = self.classes.get(&file.action) {
                        let validated = file.fields.iter().map(|(name, _)| name).collect::<HashSet<_>>();
                        findings.extend(class.fields.iter().filter(|(name, _)| !validated.contains(name)).map(|(_, offset)| (class.path.clone(), *offset)));
                    }
                }
            }
            C::Struts2ValidatorWithoutActionField => {
                for file in &self.validation_files {
                    if let Some(class) = self.classes.get(&file.action) {
                        let fields = class.fields.iter().map(|(name, _)| name).collect::<HashSet<_>>();
                        findings.extend(file.fields.iter().filter(|(name, _)| !fields.contains(name)).map(|(_, offset)| (file.path.clone(), *offset)));
                    }
                }
            }
            C::Struts2UndeclaredValidator => {
                for file in &self.validation_files {
                    findings.extend(file.validator_types.iter().filter(|(ty, _)| !builtins.contains(&ty.as_str())).map(|(_, offset)| (file.path.clone(), *offset)));
                }
            }
            C::StrutsDuplicateValidationForms => {
                for file in &self.validation_files {
                    let mut seen = HashSet::new();
                    findings.extend(file.form_names.iter().filter(|(name, _)| !seen.insert(name.clone())).map(|(_, offset)| (file.path.clone(), *offset)));
                }
            }
            C::StrutsErroneousValidateMethod => {
                for class in self.classes.values() {
                    findings.extend(class.bad_validate.iter().map(|offset| (class.path.clone(), *offset)));
                }
            }
            C::StrutsFormDoesNotExtendValidationClass | C::StrutsUnvalidatedActionForm => {
                for (form, action_ty, validate, offset, path) in &self.actions {
                    let Some((class_name, _, _)) = self.forms.get(form) else { continue };
                    let Some(class) = self.classes.get(class_name) else { continue };
                    let extends_validator = matches!(class.superclass.rsplit('.').next(), Some("ValidatorForm" | "ValidatorActionForm" | "DynaValidatorForm"));
                    let has_validation = self.validation_files.iter().any(|file| file.form_names.iter().any(|(name, _)| name == form));
                    let matches = match check {
                        C::StrutsFormDoesNotExtendValidationClass => has_validation && !extends_validator,
                        _ => *validate && !extends_validator && !has_validation && !action_ty.is_empty(),
                    };
                    if matches { findings.push((path.clone(), *offset)); }
                }
            }
            C::StrutsUnusedValidationForm => {
                let used = self.actions.iter().map(|(form, _, _, _, _)| form).collect::<HashSet<_>>();
                for file in &self.validation_files {
                    findings.extend(file.form_names.iter().filter(|(name, _)| !used.contains(name)).map(|(_, offset)| (file.path.clone(), *offset)));
                }
            }
            C::StrutsValidatorWithoutFormField | C::StrutsFormFieldWithoutValidator => {
                for file in &self.validation_files {
                    for (form_name, _) in &file.form_names {
                        let Some((class_name, _, _)) = self.forms.get(form_name) else { continue };
                        let Some(class) = self.classes.get(class_name) else { continue };
                        let form_fields = class.fields.iter().map(|(name, _)| name).collect::<HashSet<_>>();
                        let validators = file.fields.iter().map(|(name, _)| name).collect::<HashSet<_>>();
                        match check {
                            C::StrutsValidatorWithoutFormField => findings.extend(file.fields.iter().filter(|(name, _)| !form_fields.contains(name)).map(|(_, offset)| (file.path.clone(), *offset))),
                            _ => findings.extend(class.fields.iter().filter(|(name, _)| !validators.contains(name)).map(|(_, offset)| (class.path.clone(), *offset))),
                        }
                    }
                }
            }
        }
        findings.sort();
        findings.dedup();
        findings
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JavaConfigCheck {
    AndroidDebuggable,
    AndroidBackupEnabled,
    AndroidTaskReparenting,
    AndroidSingleTask,
    AndroidNormalPermission,
    AndroidDeprecatedPermission,
    AndroidExposedWithoutPermission,
    SpringActuatorSecurityDisabled,
    SpringAdminMbeanEnabled,
    SpringDevtoolsEnabled,
    SpringShutdownEndpointEnabled,
    J2eeExcessiveSessionTimeout,
    J2eeInsufficientSessionIdLength,
    J2eeCookiesDisabled,
    J2eeMissingAuthenticationMethod,
    J2eeMissingTransportConstraint,
    J2eeDebugInformation,
    J2eeDuplicateSecurityRole,
    J2eeDuplicateServletMapping,
    J2eeExcessiveServletMappings,
    J2eeIncompleteThrowableErrorHandling,
    J2eeInvalidServletName,
    J2eeMissingErrorHandling,
    J2eeMissingFilterDefinition,
    J2eeMissingSecurityRole,
    J2eeMissingServletMapping,
    J2eeUnsafeBeanDeclaration,
    J2eeWeakAccessPermissions,
    J2eeWeakSecurityConstraint,
    J2eeHttpMethodConstraint,
    InsecureDatabaseTransport,
    TomcatInsecureConnector,
    WebsphereServletByClassName,
    BuildDynamicDependencyVersion,
    BuildExternalAntRepository,
    BuildExternalIvyRepository,
    BuildExternalMavenRepository,
    DockerDefaultUserPrivilege,
    DockerPrivilegedContainer,
    DockerPrivilegedPort,
    DockerSensitiveHostDirectory,
    DockerSshService,
    AndroidProviderWriteOnlyPermission,
    AndroidProviderMissingExportOrPermission,
    AndroidMissingNetworkSecurityConfig,
    AndroidMixedReceiverFunctionality,
    AndroidProviderCombinedPermission,
    AndroidTapJackingSdk,
    AxisSoapMonitorEnabled,
    AxisMissingInflowSecurity,
    AxisRestEnabled,
    AxisMissingOutflowSecurity,
    AxisMissingRampart,
    AdfMissingUrlInvokeDisallowed,
    StrutsDuplicateFormBean,
    StrutsInvalidActionPath,
    StrutsMissingActionInput,
    StrutsMissingExceptionType,
    StrutsMissingFormBean,
    StrutsMissingFormBeanName,
    StrutsMissingFormBeanType,
    StrutsMissingFormPropertyType,
    StrutsMissingForwardName,
    StrutsMissingForwardPath,
    StrutsPluginFrameworkMissing,
    StrutsUnusedActionForm,
    StrutsValidatorDisabled,
    SpringHtmlEscapingDisabled,
    CorsWildcardOrigin,
    CrossDomainWildcard,
    CrossDomainWildcardHeaders,
    DruidDependency,
    SpringfoxDependency,
    UnsafeDeserializationDependency,
    BroadSqlLogging,
    BroadDebugLogging,
    AndroidPermissionActivityRecognition,
    AndroidPermissionCalendar,
    AndroidPermissionCallLog,
    AndroidPermissionCamera,
    AndroidPermissionContacts,
    AndroidPermissionExternalStorage,
    AndroidPermissionDeviceAdmin,
    AndroidPermissionLocation,
    AndroidPermissionMessaging,
    AndroidPermissionMicrophone,
    AndroidPermissionNetwork,
    AndroidPermissionSensors,
    AndroidPermissionTelephony,
    AndroidPermissionReview,
    Struts2DynamicMethodInvocation,
    Struts2ConfigBrowser,
    Struts2DuplicateFieldValidator,
    Struts2DuplicateValidator,
    AxisHttpTransportSender,
    AxisHttpTransportReceiver,
    SpringWebServiceExporter,
    SpringRemoteServiceExporter,
    AndroidExactPermissionPath,
    EmptyPasswordProperty,
    HardcodedPasswordProperty,
    XmlSchemaLaxProcessing,
    XmlSchemaAnyType,
    XmlSchemaUnboundedOccurrence,
    J2eeDirectJspAccess,
    AntiSamyExternalLinks,
    SpringWebflowMissingValidator,
}

impl JavaConfigCheck {
    pub(crate) fn offsets(self, path: &Path, source: &str) -> Vec<usize> {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if matches!(
            self,
            Self::SpringActuatorSecurityDisabled
                | Self::SpringAdminMbeanEnabled
                | Self::SpringShutdownEndpointEnabled
                | Self::CorsWildcardOrigin
        ) {
            return spring_property_offsets(self, path, source);
        }
        if matches!(self, Self::BroadSqlLogging | Self::BroadDebugLogging) {
            return logging_property_offsets(self, path, source);
        }
        if matches!(
            self,
            Self::EmptyPasswordProperty | Self::HardcodedPasswordProperty
        ) && matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("properties" | "yml" | "yaml")
        ) {
            return credential_property_offsets(self, path, source);
        }
        if self == Self::InsecureDatabaseTransport {
            return insecure_database_transport_offsets(path, source);
        }
        if self == Self::AntiSamyExternalLinks {
            if sxd_document::parser::parse(source).is_err() {
                return Vec::new();
            }
            return start_tags(source)
                .into_iter()
                .filter(|tag| {
                    tag.name == "regexp" && tag.attribute("name") == Some("offsiteURL")
                })
                .map(|tag| tag.offset)
                .collect();
        }
        if self == Self::SpringWebflowMissingValidator {
            if sxd_document::parser::parse(source).is_err() {
                return Vec::new();
            }
            let tags = start_tags(source);
            let has_validator = tags.iter().any(|tag| {
                tag.name == "property" && tag.attribute("name") == Some("validator")
            });
            if has_validator {
                return Vec::new();
            }
            return tags
                .into_iter()
                .filter(|tag| {
                    tag.name == "bean"
                        && tag
                            .attribute("class")
                            .is_some_and(|class| class.ends_with("FormAction"))
                })
                .map(|tag| tag.offset)
                .collect();
        }
        if self == Self::SpringDevtoolsEnabled {
            return spring_devtools_offsets(path, source);
        }
        if matches!(
            self,
            Self::BuildDynamicDependencyVersion
                | Self::BuildExternalAntRepository
                | Self::BuildExternalIvyRepository
                | Self::BuildExternalMavenRepository
        ) {
            return build_config_offsets(self, path, source);
        }
        if matches!(
            self,
            Self::DockerDefaultUserPrivilege
                | Self::DockerPrivilegedContainer
                | Self::DockerPrivilegedPort
                | Self::DockerSensitiveHostDirectory
                | Self::DockerSshService
        ) {
            return dockerfile_offsets(self, path, source);
        }
        if file_name != "AndroidManifest.xml"
            && !matches!(
                self,
                Self::J2eeExcessiveSessionTimeout
                    | Self::J2eeInsufficientSessionIdLength
                    | Self::J2eeCookiesDisabled
                    | Self::J2eeMissingAuthenticationMethod
                    | Self::J2eeMissingTransportConstraint
                    | Self::J2eeDebugInformation
                    | Self::J2eeDuplicateSecurityRole
                    | Self::J2eeDuplicateServletMapping
                    | Self::J2eeExcessiveServletMappings
                    | Self::J2eeIncompleteThrowableErrorHandling
                    | Self::J2eeInvalidServletName
                    | Self::J2eeMissingErrorHandling
                    | Self::J2eeMissingFilterDefinition
                    | Self::J2eeMissingSecurityRole
                    | Self::J2eeMissingServletMapping
                    | Self::J2eeUnsafeBeanDeclaration
                    | Self::J2eeWeakAccessPermissions
                    | Self::J2eeWeakSecurityConstraint
                    | Self::J2eeHttpMethodConstraint
                    | Self::TomcatInsecureConnector
                    | Self::WebsphereServletByClassName
                    | Self::AndroidProviderWriteOnlyPermission
                    | Self::AndroidProviderMissingExportOrPermission
                    | Self::AndroidMissingNetworkSecurityConfig
                    | Self::AndroidMixedReceiverFunctionality
                    | Self::AndroidProviderCombinedPermission
                    | Self::AndroidTapJackingSdk
                    | Self::AxisSoapMonitorEnabled
                    | Self::AxisMissingInflowSecurity
                    | Self::AxisRestEnabled
                    | Self::AxisMissingOutflowSecurity
                    | Self::AxisMissingRampart
                    | Self::AdfMissingUrlInvokeDisallowed
                    | Self::StrutsDuplicateFormBean
                    | Self::StrutsInvalidActionPath
                    | Self::StrutsMissingActionInput
                    | Self::StrutsMissingExceptionType
                    | Self::StrutsMissingFormBean
                    | Self::StrutsMissingFormBeanName
                    | Self::StrutsMissingFormBeanType
                    | Self::StrutsMissingFormPropertyType
                    | Self::StrutsMissingForwardName
                    | Self::StrutsMissingForwardPath
                    | Self::StrutsPluginFrameworkMissing
                    | Self::StrutsUnusedActionForm
                    | Self::StrutsValidatorDisabled
                    | Self::SpringHtmlEscapingDisabled
                    | Self::CrossDomainWildcard
                    | Self::CrossDomainWildcardHeaders
                    | Self::DruidDependency
                    | Self::SpringfoxDependency
                    | Self::UnsafeDeserializationDependency
                    | Self::AndroidPermissionActivityRecognition
                    | Self::AndroidPermissionCalendar
                    | Self::AndroidPermissionCallLog
                    | Self::AndroidPermissionCamera
                    | Self::AndroidPermissionContacts
                    | Self::AndroidPermissionExternalStorage
                    | Self::AndroidPermissionDeviceAdmin
                    | Self::AndroidPermissionLocation
                    | Self::AndroidPermissionMessaging
                    | Self::AndroidPermissionMicrophone
                    | Self::AndroidPermissionNetwork
                    | Self::AndroidPermissionSensors
                    | Self::AndroidPermissionTelephony
                    | Self::AndroidPermissionReview
                    | Self::Struts2DynamicMethodInvocation
                    | Self::Struts2ConfigBrowser
                    | Self::Struts2DuplicateFieldValidator
                    | Self::Struts2DuplicateValidator
                    | Self::AxisHttpTransportSender
                    | Self::AxisHttpTransportReceiver
                    | Self::SpringWebServiceExporter
                    | Self::SpringRemoteServiceExporter
                    | Self::AndroidExactPermissionPath
                    | Self::EmptyPasswordProperty
                    | Self::HardcodedPasswordProperty
                    | Self::XmlSchemaLaxProcessing
                    | Self::XmlSchemaAnyType
                    | Self::XmlSchemaUnboundedOccurrence
                    | Self::J2eeDirectJspAccess
            )
        {
            return Vec::new();
        }
        // Reject malformed XML before applying security semantics. The lexical
        // index below exists only to retain byte-accurate finding locations.
        if sxd_document::parser::parse(source).is_err() {
            return Vec::new();
        }
        let tags = start_tags(source);
        tags.iter()
            .filter(|tag| match self {
                Self::AndroidDebuggable => {
                    tag.name == "application" && tag.attribute("debuggable") == Some("true")
                }
                Self::AndroidBackupEnabled => {
                    tag.name == "application" && tag.attribute("allowBackup") != Some("false")
                }
                Self::AndroidTaskReparenting => {
                    matches!(tag.name.as_str(), "application" | "activity")
                        && tag.attribute("allowTaskReparenting") == Some("true")
                }
                Self::AndroidSingleTask => {
                    tag.name == "activity" && tag.attribute("launchMode") == Some("singleTask")
                }
                Self::AndroidNormalPermission => {
                    tag.name == "permission"
                        && tag
                            .attribute("protectionLevel")
                            .is_none_or(|value| value == "normal")
                }
                Self::AndroidDeprecatedPermission => {
                    tag.name == "permission"
                        && tag
                            .attribute("protectionLevel")
                            .is_some_and(|value| matches!(value, "signatureOrSystem" | "system"))
                }
                Self::AndroidExposedWithoutPermission => {
                    matches!(
                        tag.name.as_str(),
                        "activity" | "activity-alias" | "service" | "receiver" | "provider"
                    ) && tag.attribute("exported") == Some("true")
                        && tag.attribute("permission").is_none()
                        && tag.attribute("readPermission").is_none()
                        && tag.attribute("writePermission").is_none()
                }
                Self::AndroidProviderWriteOnlyPermission => {
                    tag.name == "provider"
                        && tag.attribute("writePermission").is_some()
                        && tag.attribute("readPermission").is_none()
                }
                Self::AndroidProviderMissingExportOrPermission => {
                    tag.name == "provider"
                        && tag.attribute("exported").is_none()
                        && tag.attribute("permission").is_none()
                        && tag.attribute("readPermission").is_none()
                        && tag.attribute("writePermission").is_none()
                }
                Self::AndroidMissingNetworkSecurityConfig => {
                    tag.name == "application" && tag.attribute("networkSecurityConfig").is_none()
                }
                Self::AndroidMixedReceiverFunctionality => {
                    tag.name == "receiver" && {
                        let actions = descendants(&tags, source, tag)
                            .filter(|child| child.name == "action")
                            .filter_map(|child| child.attribute("name"))
                            .collect::<Vec<_>>();
                        actions.iter().any(|name| is_android_system_action(name))
                            && actions.iter().any(|name| !is_android_system_action(name))
                    }
                }
                Self::AndroidProviderCombinedPermission => {
                    tag.name == "provider"
                        && tag.attribute("permission").is_some()
                        && tag.attribute("readPermission").is_none()
                        && tag.attribute("writePermission").is_none()
                }
                Self::AndroidTapJackingSdk => {
                    (tag.name == "uses-sdk"
                        && tag
                            .attribute("minSdkVersion")
                            .and_then(|value| value.parse::<u64>().ok())
                            .is_some_and(|version| version < 9))
                        || (tag.name == "manifest"
                            && !tags.iter().any(|candidate| candidate.name == "uses-sdk"))
                }
                Self::J2eeExcessiveSessionTimeout => {
                    file_name == "web.xml"
                        && tag.name == "session-timeout"
                        && element_text(source, tag)
                            .and_then(|value| value.parse::<i64>().ok())
                            .is_some_and(|minutes| minutes < 0 || minutes > 30)
                }
                Self::J2eeInsufficientSessionIdLength => {
                    tag.name == "id-length"
                        && has_ancestor(source, &tags, tag, "session-descriptor")
                        && element_text(source, tag)
                            .and_then(|value| value.parse::<u64>().ok())
                            .is_some_and(|length| length < 16)
                }
                Self::J2eeCookiesDisabled => {
                    (file_name == "web.xml"
                        && tag.name == "tracking-mode"
                        && element_text(source, tag)
                            .is_some_and(|value| !value.eq_ignore_ascii_case("COOKIE")))
                        || (tag.name == "cookies-enabled"
                            && element_text(source, tag)
                                .is_some_and(|value| value.eq_ignore_ascii_case("false")))
                }
                Self::J2eeMissingAuthenticationMethod => {
                    file_name == "web.xml"
                        && tag.name == "web-app"
                        && descendants(&tags, source, tag)
                            .any(|child| child.name == "auth-constraint")
                        && !descendants(&tags, source, tag).any(|child| {
                            child.name == "auth-method"
                                && element_text(source, child).is_some_and(|value| {
                                    matches!(
                                        value.to_ascii_uppercase().as_str(),
                                        "BASIC" | "FORM" | "DIGEST" | "CLIENT_CERT"
                                    )
                                })
                        })
                }
                Self::J2eeMissingTransportConstraint => {
                    file_name == "web.xml"
                        && tag.name == "security-constraint"
                        && descendants(&tags, source, tag)
                            .any(|child| child.name == "auth-constraint")
                        && !descendants(&tags, source, tag).any(|child| {
                            child.name == "transport-guarantee"
                                && element_text(source, child)
                                    .is_some_and(|value| value.eq_ignore_ascii_case("CONFIDENTIAL"))
                        })
                }
                Self::J2eeDebugInformation => {
                    tag.name.eq_ignore_ascii_case("Realm")
                        && tag
                            .attribute("debug")
                            .and_then(|value| value.parse::<u64>().ok())
                            .is_some_and(|level| level >= 3)
                }
                Self::J2eeDuplicateSecurityRole => {
                    tag.name == "role-name"
                        && has_ancestor(source, &tags, tag, "security-role")
                        && element_text(source, tag).is_some_and(|value| {
                            tags.iter().any(|earlier| {
                                earlier.offset < tag.offset
                                    && earlier.name == "role-name"
                                    && has_ancestor(source, &tags, earlier, "security-role")
                                    && element_text(source, earlier) == Some(value)
                            })
                        })
                }
                Self::J2eeDuplicateServletMapping => {
                    tag.name == "url-pattern"
                        && has_ancestor(source, &tags, tag, "servlet-mapping")
                        && element_text(source, tag).is_some_and(|value| {
                            tags.iter().any(|earlier| {
                                earlier.offset < tag.offset
                                    && earlier.name == "url-pattern"
                                    && has_ancestor(source, &tags, earlier, "servlet-mapping")
                                    && element_text(source, earlier) == Some(value)
                            })
                        })
                }
                Self::J2eeExcessiveServletMappings => {
                    tag.name == "servlet-mapping"
                        && descendants(&tags, source, tag)
                            .filter(|child| child.name == "url-pattern")
                            .count()
                            > 1
                }
                Self::J2eeIncompleteThrowableErrorHandling => {
                    file_name == "web.xml"
                        && tag.name == "web-app"
                        && !descendants(&tags, source, tag).any(|child| {
                            child.name == "exception-type"
                                && element_text(source, child) == Some("java.lang.Throwable")
                        })
                }
                Self::J2eeInvalidServletName => {
                    tag.name == "servlet" && {
                        let names = descendants(&tags, source, tag)
                            .filter(|child| child.name == "servlet-name")
                            .collect::<Vec<_>>();
                        names.len() != 1
                            || names
                                .first()
                                .and_then(|name| element_text(source, name))
                                .is_none_or(str::is_empty)
                    }
                }
                Self::J2eeMissingErrorHandling => {
                    file_name == "web.xml"
                        && tag.name == "web-app"
                        && !descendants(&tags, source, tag).any(|child| child.name == "error-page")
                }
                Self::J2eeMissingFilterDefinition => {
                    tag.name == "filter-mapping"
                        && descendant_text(&tags, source, tag, "filter-name").is_some_and(|name| {
                            !tags.iter().any(|definition| {
                                definition.name == "filter"
                                    && descendant_text(&tags, source, definition, "filter-name")
                                        == Some(name)
                            })
                        })
                }
                Self::J2eeMissingSecurityRole => {
                    tag.name == "role-name"
                        && has_ancestor(source, &tags, tag, "auth-constraint")
                        && element_text(source, tag).is_some_and(|name| {
                            !tags.iter().any(|role| {
                                role.name == "security-role"
                                    && descendant_text(&tags, source, role, "role-name")
                                        == Some(name)
                            })
                        })
                }
                Self::J2eeMissingServletMapping => {
                    tag.name == "servlet"
                        && descendant_text(&tags, source, tag, "servlet-name").is_some_and(|name| {
                            !tags.iter().any(|mapping| {
                                mapping.name == "servlet-mapping"
                                    && descendant_text(&tags, source, mapping, "servlet-name")
                                        == Some(name)
                            })
                        })
                }
                Self::J2eeUnsafeBeanDeclaration => {
                    tag.name == "entity"
                        && descendants(&tags, source, tag).any(|child| {
                            child.name == "remote"
                                && element_text(source, child)
                                    .is_some_and(|value| !value.is_empty())
                        })
                }
                Self::J2eeWeakAccessPermissions => {
                    tag.name == "role-name"
                        && has_ancestor(source, &tags, tag, "method-permission")
                        && element_text(source, tag)
                            .is_some_and(|value| value.eq_ignore_ascii_case("ANYONE"))
                }
                Self::J2eeWeakSecurityConstraint => {
                    tag.name == "url-pattern"
                        && element_text(source, tag).is_some_and(|value| value.contains('*'))
                        && has_ancestor(source, &tags, tag, "security-constraint")
                }
                Self::J2eeHttpMethodConstraint => {
                    file_name == "web.xml"
                        && tag.name == "http-method"
                        && has_ancestor(source, &tags, tag, "security-constraint")
                }
                Self::TomcatInsecureConnector => {
                    tag.name.eq_ignore_ascii_case("Connector")
                        && tag
                            .attribute("protocol")
                            .is_some_and(|protocol| protocol.to_ascii_uppercase().contains("HTTP"))
                        && tag.attribute("secure") != Some("true")
                }
                Self::WebsphereServletByClassName => {
                    tag.attribute("serveServletsByClassnameEnabled") == Some("true")
                        || (tag.name == "enable-serving-servlets-by-class-name"
                            && element_text(source, tag)
                                .is_some_and(|value| value.eq_ignore_ascii_case("true")))
                }
                Self::AxisSoapMonitorEnabled => {
                    ((tag.name == "servlet-name" || tag.name == "servlet-class")
                        && element_text(source, tag)
                            .is_some_and(|value| value.contains("SOAPMonitor")))
                        || (tag.name == "module"
                            && tag
                                .attribute("ref")
                                .is_some_and(|value| value.eq_ignore_ascii_case("soapmonitor")))
                }
                Self::AxisMissingInflowSecurity => {
                    file_name == "axis2.xml"
                        && tag.name == "axisconfig"
                        && !descendants(&tags, source, tag).any(|child| {
                            child.name == "parameter"
                                && child.attribute("name") == Some("InflowSecurity")
                        })
                }
                Self::AxisRestEnabled => {
                    file_name == "axis2.xml"
                        && tag.name == "parameter"
                        && tag.attribute("name") == Some("disableREST")
                        && element_text(source, tag)
                            .is_some_and(|value| value.eq_ignore_ascii_case("false"))
                }
                Self::AxisMissingOutflowSecurity => {
                    file_name == "axis2.xml"
                        && tag.name == "axisconfig"
                        && !descendants(&tags, source, tag).any(|child| {
                            child.name == "parameter"
                                && child.attribute("name") == Some("OutflowSecurity")
                        })
                }
                Self::AxisMissingRampart => {
                    file_name == "axis2.xml"
                        && tag.name == "axisconfig"
                        && !descendants(&tags, source, tag).any(|child| {
                            child.name == "module"
                                && child
                                    .attribute("ref")
                                    .is_some_and(|value| value.eq_ignore_ascii_case("rampart"))
                        })
                }
                Self::AdfMissingUrlInvokeDisallowed => {
                    tag.name == "task-flow-definition"
                        && !descendants(&tags, source, tag)
                            .any(|child| child.name == "url-invoke-disallowed")
                }
                Self::StrutsDuplicateFormBean => {
                    tag.name == "form-bean"
                        && tag.attribute("name").is_some_and(|name| {
                            tags.iter().any(|earlier| {
                                earlier.offset < tag.offset
                                    && earlier.name == "form-bean"
                                    && earlier.attribute("name") == Some(name)
                            })
                        })
                }
                Self::StrutsInvalidActionPath => {
                    tag.name == "action"
                        && tag
                            .attribute("path")
                            .is_none_or(|path| !path.starts_with('/'))
                }
                Self::StrutsMissingActionInput => {
                    tag.name == "action"
                        && tag.attribute("name").is_some()
                        && tag.attribute("validate") != Some("false")
                        && tag.attribute("input").is_none_or(str::is_empty)
                }
                Self::StrutsMissingExceptionType => {
                    tag.name == "exception" && tag.attribute("type").is_none_or(str::is_empty)
                }
                Self::StrutsMissingFormBean => {
                    tag.name == "action"
                        && tag.attribute("name").is_some_and(|name| {
                            !tags.iter().any(|bean| {
                                bean.name == "form-bean" && bean.attribute("name") == Some(name)
                            })
                        })
                }
                Self::StrutsMissingFormBeanName => {
                    tag.name == "form-bean" && tag.attribute("name").is_none_or(str::is_empty)
                }
                Self::StrutsMissingFormBeanType => {
                    tag.name == "form-bean" && tag.attribute("type").is_none_or(str::is_empty)
                }
                Self::StrutsMissingFormPropertyType => {
                    tag.name == "form-property" && tag.attribute("type").is_none_or(str::is_empty)
                }
                Self::StrutsMissingForwardName => {
                    tag.name == "forward" && tag.attribute("name").is_none_or(str::is_empty)
                }
                Self::StrutsMissingForwardPath => {
                    tag.name == "forward" && tag.attribute("path").is_none_or(str::is_empty)
                }
                Self::StrutsPluginFrameworkMissing => {
                    tag.name == "struts-config"
                        && !descendants(&tags, source, tag).any(|child| {
                            child.name == "plug-in"
                                && child.attribute("className").is_some_and(|name| {
                                    name.ends_with(".ValidatorPlugIn") || name == "ValidatorPlugIn"
                                })
                        })
                }
                Self::StrutsUnusedActionForm => {
                    tag.name == "form-bean"
                        && tag.attribute("name").is_some_and(|name| {
                            !tags.iter().any(|action| {
                                action.name == "action" && action.attribute("name") == Some(name)
                            })
                        })
                }
                Self::StrutsValidatorDisabled => {
                    tag.name == "action" && tag.attribute("validate") == Some("false")
                }
                Self::SpringHtmlEscapingDisabled => {
                    tag.name == "htmlEscape" && tag.attribute("defaultHtmlEscape") == Some("false")
                }
                Self::CrossDomainWildcard => {
                    (tag.name == "domain" && tag.attribute("uri") == Some("*"))
                        || (tag.name == "allow-access-from" && tag.attribute("domain") == Some("*"))
                }
                Self::CrossDomainWildcardHeaders => {
                    tag.name == "allow-http-request-headers-from"
                        && tag.attribute("headers") == Some("*")
                }
                Self::DruidDependency => {
                    tag.name == "dependency"
                        && descendant_text(&tags, source, tag, "groupId") == Some("com.alibaba")
                        && descendant_text(&tags, source, tag, "artifactId").is_some_and(|value| {
                            value == "druid" || value == "druid-spring-boot-starter"
                        })
                }
                Self::SpringfoxDependency => {
                    tag.name == "dependency"
                        && descendant_text(&tags, source, tag, "groupId") == Some("io.springfox")
                        && descendant_text(&tags, source, tag, "artifactId").is_some_and(|value| {
                            value.contains("swagger") || value.contains("springfox")
                        })
                }
                Self::UnsafeDeserializationDependency => {
                    tag.name == "dependency"
                        && descendant_text(&tags, source, tag, "groupId")
                            == Some("org.springframework.boot")
                        && descendant_text(&tags, source, tag, "artifactId")
                            == Some("spring-boot-starter-actuator")
                }
                Self::AndroidPermissionActivityRecognition
                | Self::AndroidPermissionCalendar
                | Self::AndroidPermissionCallLog
                | Self::AndroidPermissionCamera
                | Self::AndroidPermissionContacts
                | Self::AndroidPermissionExternalStorage
                | Self::AndroidPermissionDeviceAdmin
                | Self::AndroidPermissionLocation
                | Self::AndroidPermissionMessaging
                | Self::AndroidPermissionMicrophone
                | Self::AndroidPermissionNetwork
                | Self::AndroidPermissionSensors
                | Self::AndroidPermissionTelephony => {
                    tag.name == "uses-permission"
                        && tag
                            .attribute("name")
                            .is_some_and(|name| android_permission_matches(self, name))
                }
                Self::AndroidPermissionReview => tag.name == "uses-permission",
                Self::Struts2DynamicMethodInvocation => {
                    tag.name == "struts"
                        && !descendants(&tags, source, tag).any(|child| {
                            child.name == "constant"
                                && child.attribute("name")
                                    == Some("struts.enable.DynamicMethodInvocation")
                                && child
                                    .attribute("value")
                                    .is_some_and(|value| value.eq_ignore_ascii_case("false"))
                        })
                }
                Self::Struts2ConfigBrowser => {
                    (tag.name == "package"
                        && tag.attribute("extends").is_some_and(|value| {
                            value
                                .split(',')
                                .any(|base| base.trim() == "config-browser-default")
                        }))
                        || (tag.name == "dependency"
                            && descendant_text(&tags, source, tag, "artifactId")
                                .is_some_and(|value| value.contains("config-browser")))
                }
                Self::Struts2DuplicateFieldValidator => {
                    tag.name == "field-validator"
                        && tag.attribute("type").is_some_and(|ty| {
                            tags.iter().any(|earlier| {
                                earlier.offset < tag.offset
                                    && earlier.name == "field-validator"
                                    && earlier.attribute("type") == Some(ty)
                                    && tags.iter().any(|field| {
                                        field.name == "field"
                                            && field.offset < earlier.offset
                                            && tag.offset
                                                < element_end_offset(source, field)
                                                    .unwrap_or(field.end)
                                    })
                            })
                        })
                }
                Self::Struts2DuplicateValidator => {
                    tag.name == "validator"
                        && tag.attribute("name").is_some_and(|name| {
                            tags.iter().any(|earlier| {
                                earlier.offset < tag.offset
                                    && earlier.name == "validator"
                                    && earlier.attribute("name") == Some(name)
                            })
                        })
                }
                Self::AxisHttpTransportSender => {
                    tag.name == "transportSender"
                        && tag
                            .attribute("name")
                            .is_some_and(|value| value.eq_ignore_ascii_case("http"))
                }
                Self::AxisHttpTransportReceiver => {
                    tag.name == "transportReceiver"
                        && tag
                            .attribute("name")
                            .is_some_and(|value| value.eq_ignore_ascii_case("http"))
                }
                Self::SpringWebServiceExporter => {
                    tag.name == "bean"
                        && tag.attribute("class").is_some_and(|value| {
                            matches!(
                                value.rsplit('.').next(),
                                Some("SimpleJaxWsServiceExporter" | "XFireExporter")
                            )
                        })
                }
                Self::SpringRemoteServiceExporter => {
                    tag.name == "bean"
                        && tag.attribute("class").is_some_and(|value| {
                            [
                                "HttpInvokerServiceExporter",
                                "HessianServiceExporter",
                                "BurlapServiceExporter",
                                "RmiServiceExporter",
                                "JaxWsPortProxyFactoryBean",
                            ]
                            .iter()
                            .any(|class| value.rsplit('.').next() == Some(class))
                        })
                }
                Self::AndroidExactPermissionPath => {
                    matches!(
                        tag.name.as_str(),
                        "provider" | "path-permission" | "grant-uri-permission"
                    ) && tag.attribute("path").is_some()
                }
                Self::EmptyPasswordProperty | Self::HardcodedPasswordProperty => {
                    tag.name == "property"
                        && tag.attribute("name").is_some_and(sensitive_property_key)
                        && tag.attribute("value").is_some_and(|value| {
                            if self == Self::EmptyPasswordProperty {
                                value.trim().is_empty()
                            } else {
                                !value.trim().is_empty()
                                    && !value.contains("${")
                                    && !value.starts_with("ENC(")
                            }
                        })
                }
                Self::XmlSchemaLaxProcessing => {
                    tag.name == "any"
                        && tag.attribute("processContents").is_some_and(|value| {
                            matches!(value.to_ascii_lowercase().as_str(), "lax" | "skip")
                        })
                }
                Self::XmlSchemaAnyType => {
                    matches!(tag.name.as_str(), "element" | "attribute")
                        && tag
                            .attribute("type")
                            .is_some_and(|value| value.rsplit(':').next() == Some("anyType"))
                }
                Self::XmlSchemaUnboundedOccurrence => {
                    matches!(tag.name.as_str(), "element" | "any" | "sequence" | "choice")
                        && tag.attribute("maxOccurs") == Some("unbounded")
                }
                Self::J2eeDirectJspAccess => {
                    tag.name == "url-pattern"
                        && element_text(source, tag)
                            .is_some_and(|value| value.ends_with(".jsp") || value.contains("*.jsp"))
                }
                Self::SpringActuatorSecurityDisabled
                | Self::SpringAdminMbeanEnabled
                | Self::SpringDevtoolsEnabled
                | Self::SpringShutdownEndpointEnabled
                | Self::CorsWildcardOrigin
                | Self::BroadSqlLogging
                | Self::BroadDebugLogging
                | Self::InsecureDatabaseTransport
                | Self::BuildDynamicDependencyVersion
                | Self::BuildExternalAntRepository
                | Self::BuildExternalIvyRepository
                | Self::BuildExternalMavenRepository
                | Self::DockerDefaultUserPrivilege
                | Self::DockerPrivilegedContainer
                | Self::DockerPrivilegedPort
                | Self::DockerSensitiveHostDirectory
                | Self::DockerSshService
                | Self::AntiSamyExternalLinks
                | Self::SpringWebflowMissingValidator => false,
            })
            .map(|tag| tag.offset)
            .collect()
    }
}

#[derive(Debug)]
struct StartTag {
    name: String,
    attributes: Vec<(String, String)>,
    offset: usize,
    end: usize,
    self_closing: bool,
}

impl StartTag {
    fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }
}

fn local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

/// XML start-tag index with quote-aware `>` handling. XML validity and
/// namespace handling are delegated to sxd-document before this runs.
fn start_tags(source: &str) -> Vec<StartTag> {
    let bytes = source.as_bytes();
    let mut tags = Vec::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        let Some(relative) = source[cursor..].find('<') else {
            break;
        };
        let start = cursor + relative;
        if source[start..].starts_with("<!--") {
            cursor = source[start + 4..]
                .find("-->")
                .map_or(bytes.len(), |end| start + 4 + end + 3);
            continue;
        }
        if source[start..].starts_with("<![CDATA[") {
            cursor = source[start + 9..]
                .find("]]>")
                .map_or(bytes.len(), |end| start + 9 + end + 3);
            continue;
        }
        if source[start..].starts_with("<?") {
            cursor = source[start + 2..]
                .find("?>")
                .map_or(bytes.len(), |end| start + 2 + end + 2);
            continue;
        }
        if bytes
            .get(start + 1)
            .is_some_and(|byte| matches!(byte, b'/' | b'!'))
        {
            cursor = quoted_tag_end(bytes, start + 1).map_or(bytes.len(), |end| end + 1);
            continue;
        }
        let Some(end) = quoted_tag_end(bytes, start + 1) else {
            break;
        };
        if let Some(tag) = parse_start_tag(&source[start + 1..end], start) {
            tags.push(tag);
        }
        cursor = end + 1;
    }
    tags
}

fn quoted_tag_end(bytes: &[u8], mut cursor: usize) -> Option<usize> {
    let mut quote = None;
    while cursor < bytes.len() {
        match (quote, bytes[cursor]) {
            (Some(current), byte) if byte == current => quote = None,
            (None, byte @ (b'\'' | b'"')) => quote = Some(byte),
            (None, b'>') => return Some(cursor),
            _ => {}
        }
        cursor += 1;
    }
    None
}

fn parse_start_tag(text: &str, offset: usize) -> Option<StartTag> {
    let bytes = text.as_bytes();
    let mut cursor = 0;
    skip_space(bytes, &mut cursor);
    let name_start = cursor;
    take_name(bytes, &mut cursor);
    if cursor == name_start {
        return None;
    }
    let name = local_name(&text[name_start..cursor]).to_string();
    let mut attributes = Vec::new();
    while cursor < bytes.len() {
        skip_space(bytes, &mut cursor);
        if cursor >= bytes.len() || bytes[cursor] == b'/' {
            break;
        }
        let attribute_start = cursor;
        take_name(bytes, &mut cursor);
        if cursor == attribute_start {
            cursor += 1;
            continue;
        }
        let attribute = local_name(&text[attribute_start..cursor]).to_string();
        skip_space(bytes, &mut cursor);
        if bytes.get(cursor) != Some(&b'=') {
            continue;
        }
        cursor += 1;
        skip_space(bytes, &mut cursor);
        let quote = *bytes.get(cursor)?;
        if !matches!(quote, b'\'' | b'"') {
            return None;
        }
        cursor += 1;
        let value_start = cursor;
        while cursor < bytes.len() && bytes[cursor] != quote {
            cursor += 1;
        }
        let value = text.get(value_start..cursor)?.to_string();
        attributes.push((attribute, value));
        cursor += usize::from(cursor < bytes.len());
    }
    Some(StartTag {
        name,
        attributes,
        offset,
        end: offset + text.len() + 1,
        self_closing: text.trim_end().ends_with('/'),
    })
}

fn skip_space(bytes: &[u8], cursor: &mut usize) {
    while bytes.get(*cursor).is_some_and(u8::is_ascii_whitespace) {
        *cursor += 1;
    }
}

fn take_name(bytes: &[u8], cursor: &mut usize) {
    while bytes.get(*cursor).is_some_and(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
    }) {
        *cursor += 1;
    }
}

fn element_end_offset(source: &str, tag: &StartTag) -> Option<usize> {
    if tag.self_closing {
        return Some(tag.end + 1);
    }
    let bytes = source.as_bytes();
    let mut cursor = tag.end + 1;
    let mut depth = 1usize;
    while cursor < bytes.len() {
        let relative = source[cursor..].find('<')?;
        let start = cursor + relative;
        if source[start..].starts_with("<!--") {
            cursor = source[start + 4..]
                .find("-->")
                .map_or(bytes.len(), |end| start + 4 + end + 3);
            continue;
        }
        if source[start..].starts_with("<![CDATA[") {
            cursor = source[start + 9..]
                .find("]]>")
                .map_or(bytes.len(), |end| start + 9 + end + 3);
            continue;
        }
        if source[start..].starts_with("<?") {
            cursor = source[start + 2..]
                .find("?>")
                .map_or(bytes.len(), |end| start + 2 + end + 2);
            continue;
        }
        let end = quoted_tag_end(bytes, start + 1)?;
        if source[start..].starts_with("</") {
            let name = source[start + 2..end]
                .trim()
                .split_ascii_whitespace()
                .next()
                .map(local_name)
                .unwrap_or_default();
            if name == tag.name {
                depth -= 1;
                if depth == 0 {
                    return Some(start);
                }
            }
        } else if !source[start..].starts_with("<!") {
            if let Some(nested) = parse_start_tag(&source[start + 1..end], start) {
                if nested.name == tag.name && !nested.self_closing {
                    depth += 1;
                }
            }
        }
        cursor = end + 1;
    }
    None
}

fn element_text<'a>(source: &'a str, tag: &StartTag) -> Option<&'a str> {
    let end = element_end_offset(source, tag)?;
    let text = source.get(tag.end + 1..end)?.trim();
    (!text.contains('<')).then_some(text)
}

fn descendants<'a>(
    tags: &'a [StartTag],
    source: &str,
    parent: &StartTag,
) -> impl Iterator<Item = &'a StartTag> {
    let end = element_end_offset(source, parent).unwrap_or(parent.end + 1);
    let start = parent.offset;
    tags.iter()
        .filter(move |tag| tag.offset > start && tag.offset < end)
}

fn has_ancestor(source: &str, tags: &[StartTag], child: &StartTag, name: &str) -> bool {
    tags.iter().any(|candidate| {
        candidate.name == name
            && candidate.offset < child.offset
            && element_end_offset(source, candidate).is_some_and(|end| child.offset < end)
    })
}

fn descendant_text<'a>(
    tags: &[StartTag],
    source: &'a str,
    parent: &StartTag,
    name: &str,
) -> Option<&'a str> {
    descendants(tags, source, parent)
        .find(|child| child.name == name)
        .and_then(|child| element_text(source, child))
}

fn is_android_system_action(name: &str) -> bool {
    name.starts_with("android.intent.action.")
        || name.starts_with("android.net.")
        || name.starts_with("android.provider.")
        || name.starts_with("android.bluetooth.")
}

fn android_permission_matches(check: JavaConfigCheck, name: &str) -> bool {
    let permission = name.rsplit('.').next().unwrap_or(name);
    match check {
        JavaConfigCheck::AndroidPermissionActivityRecognition => {
            permission == "ACTIVITY_RECOGNITION"
        }
        JavaConfigCheck::AndroidPermissionCalendar => {
            matches!(permission, "READ_CALENDAR" | "WRITE_CALENDAR")
        }
        JavaConfigCheck::AndroidPermissionCallLog => {
            matches!(permission, "READ_CALL_LOG" | "WRITE_CALL_LOG")
        }
        JavaConfigCheck::AndroidPermissionCamera => permission == "CAMERA",
        JavaConfigCheck::AndroidPermissionContacts => matches!(
            permission,
            "READ_CONTACTS" | "WRITE_CONTACTS" | "GET_ACCOUNTS"
        ),
        JavaConfigCheck::AndroidPermissionExternalStorage => matches!(
            permission,
            "READ_EXTERNAL_STORAGE" | "WRITE_EXTERNAL_STORAGE" | "MANAGE_EXTERNAL_STORAGE"
        ),
        JavaConfigCheck::AndroidPermissionDeviceAdmin => {
            matches!(permission, "BIND_DEVICE_ADMIN" | "DISABLE_KEYGUARD")
        }
        JavaConfigCheck::AndroidPermissionLocation => matches!(
            permission,
            "ACCESS_FINE_LOCATION" | "ACCESS_COARSE_LOCATION" | "ACCESS_BACKGROUND_LOCATION"
        ),
        JavaConfigCheck::AndroidPermissionMessaging => matches!(
            permission,
            "SEND_SMS" | "RECEIVE_SMS" | "READ_SMS" | "WRITE_SMS" | "RECEIVE_MMS"
        ),
        JavaConfigCheck::AndroidPermissionMicrophone => permission == "RECORD_AUDIO",
        JavaConfigCheck::AndroidPermissionNetwork => permission == "INTERNET",
        JavaConfigCheck::AndroidPermissionSensors => {
            matches!(permission, "BODY_SENSORS" | "BODY_SENSORS_BACKGROUND")
        }
        JavaConfigCheck::AndroidPermissionTelephony => matches!(
            permission,
            "CALL_PHONE"
                | "READ_PHONE_STATE"
                | "READ_PHONE_NUMBERS"
                | "ANSWER_PHONE_CALLS"
                | "PROCESS_OUTGOING_CALLS"
        ),
        _ => false,
    }
}

#[derive(Debug)]
struct PropertyEntry {
    key: String,
    value: String,
    offset: usize,
}

fn spring_property_offsets(check: JavaConfigCheck, path: &Path, source: &str) -> Vec<usize> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !file_name.starts_with("application") {
        return Vec::new();
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let entries = match extension {
        "properties" => property_entries(source),
        "yml" | "yaml" if serde_yaml::from_str::<serde_yaml::Value>(source).is_ok() => {
            yaml_entries(source)
        }
        _ => Vec::new(),
    };
    entries
        .into_iter()
        .filter(|entry| {
            let value = entry.value.trim().trim_matches(['\'', '"']);
            match check {
                JavaConfigCheck::SpringActuatorSecurityDisabled => {
                    value.eq_ignore_ascii_case("false")
                        && (entry.key == "management.security.enabled"
                            || (entry.key.starts_with("endpoints.")
                                && entry.key.ends_with(".sensitive")))
                }
                JavaConfigCheck::SpringAdminMbeanEnabled => {
                    entry.key == "spring.application.admin.enabled"
                        && value.eq_ignore_ascii_case("true")
                }
                JavaConfigCheck::SpringShutdownEndpointEnabled => {
                    matches!(
                        entry.key.as_str(),
                        "endpoints.shutdown.enabled" | "management.endpoint.shutdown.enabled"
                    ) && value.eq_ignore_ascii_case("true")
                }
                JavaConfigCheck::CorsWildcardOrigin => {
                    matches!(
                        entry.key.as_str(),
                        "endpoints.cors.allowed-origins"
                            | "management.endpoints.web.cors.allowed-origins"
                            | "spring.web.cors.allowed-origins"
                    ) && value.split(',').any(|origin| origin.trim() == "*")
                }
                _ => false,
            }
        })
        .map(|entry| entry.offset)
        .collect()
}

fn logging_property_offsets(check: JavaConfigCheck, path: &Path, source: &str) -> Vec<usize> {
    if path.extension().and_then(|value| value.to_str()) != Some("properties") {
        return Vec::new();
    }
    property_entries(source)
        .into_iter()
        .filter(|entry| {
            let key = entry.key.to_ascii_lowercase();
            let value = entry.value.trim().to_ascii_uppercase();
            match check {
                JavaConfigCheck::BroadSqlLogging => {
                    (key.contains("hibernate") || key.contains("jdbc") || key.contains("sql"))
                        && matches!(value.as_str(), "ALL" | "TRACE" | "DEBUG" | "INFO")
                }
                JavaConfigCheck::BroadDebugLogging => {
                    (key == "log4j.rootlogger"
                        || key == "log4j.rootcategory"
                        || key == "logging.level.root"
                        || key == "rootlogger.level")
                        && value
                            .split([',', ' '])
                            .any(|level| matches!(level, "ALL" | "TRACE" | "DEBUG"))
                }
                _ => false,
            }
        })
        .map(|entry| entry.offset)
        .collect()
}

fn credential_property_offsets(check: JavaConfigCheck, path: &Path, source: &str) -> Vec<usize> {
    let entries = match path.extension().and_then(|value| value.to_str()) {
        Some("properties") => property_entries(source),
        Some("yml" | "yaml") if serde_yaml::from_str::<serde_yaml::Value>(source).is_ok() => {
            yaml_entries(source)
        }
        _ => Vec::new(),
    };
    entries
        .into_iter()
        .filter(|entry| {
            if !sensitive_property_key(&entry.key) {
                return false;
            }
            let value = entry.value.trim().trim_matches(['\'', '"']);
            match check {
                JavaConfigCheck::EmptyPasswordProperty => value.is_empty(),
                JavaConfigCheck::HardcodedPasswordProperty => {
                    !value.is_empty() && !value.contains("${") && !value.starts_with("ENC(")
                }
                _ => false,
            }
        })
        .map(|entry| entry.offset)
        .collect()
}

fn sensitive_property_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "pwd",
        "secret",
        "credential",
        "api-key",
        "apikey",
    ]
    .iter()
    .any(|part| key.split(['.', '-', '_']).any(|segment| segment == *part))
}

fn property_entries(source: &str) -> Vec<PropertyEntry> {
    source
        .split_inclusive('\n')
        .scan(0usize, |offset, line| {
            let current = *offset;
            *offset += line.len();
            Some((current, line))
        })
        .filter_map(|(line_offset, line)| {
            let leading = line.len() - line.trim_start().len();
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', '!']) {
                return None;
            }
            let bytes = line.as_bytes();
            let mut escaped = false;
            let separator = bytes.iter().position(|byte| {
                if escaped {
                    escaped = false;
                    return false;
                }
                if *byte == b'\\' {
                    escaped = true;
                    return false;
                }
                matches!(byte, b'=' | b':') || byte.is_ascii_whitespace()
            })?;
            let mut value_start = separator;
            while bytes
                .get(value_start)
                .is_some_and(|byte| byte.is_ascii_whitespace() || matches!(byte, b'=' | b':'))
            {
                value_start += 1;
            }
            Some(PropertyEntry {
                key: unescape_property(&line[..separator]),
                value: unescape_property(&line[value_start..]),
                offset: line_offset + leading,
            })
        })
        .collect()
}

fn unescape_property(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('f') => out.push('\u{000c}'),
            Some('u') => {
                let digits = chars.by_ref().take(4).collect::<String>();
                if let Ok(code) = u32::from_str_radix(&digits, 16) {
                    if let Some(decoded) = char::from_u32(code) {
                        out.push(decoded);
                    }
                }
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

fn yaml_entries(source: &str) -> Vec<PropertyEntry> {
    let mut stack: Vec<(usize, String)> = Vec::new();
    let mut entries = Vec::new();
    let mut offset = 0usize;
    for physical in source.split_inclusive('\n') {
        let line_offset = offset;
        offset += physical.len();
        let indent = physical.len() - physical.trim_start_matches([' ', '\t']).len();
        let text = strip_yaml_comment(physical.trim());
        if text.is_empty() || text.starts_with('-') {
            continue;
        }
        let Some(colon) = yaml_colon(text) else {
            continue;
        };
        let key = text[..colon].trim().trim_matches(['\'', '"']).to_string();
        let value = text[colon + 1..].trim();
        while stack.last().is_some_and(|(level, _)| *level >= indent) {
            stack.pop();
        }
        let full_key = stack
            .iter()
            .map(|(_, key)| key.as_str())
            .chain(std::iter::once(key.as_str()))
            .collect::<Vec<_>>()
            .join(".");
        if value.is_empty() {
            stack.push((indent, key));
        } else {
            entries.push(PropertyEntry {
                key: full_key,
                value: value.trim_matches(['\'', '"']).to_string(),
                offset: line_offset + indent,
            });
        }
    }
    entries
}

fn strip_yaml_comment(line: &str) -> &str {
    let mut quote = None;
    for (index, byte) in line.bytes().enumerate() {
        match (quote, byte) {
            (Some(current), value) if value == current => quote = None,
            (None, value @ (b'\'' | b'"')) => quote = Some(value),
            (None, b'#') => return line[..index].trim_end(),
            _ => {}
        }
    }
    line.trim_end()
}

fn yaml_colon(line: &str) -> Option<usize> {
    let mut quote = None;
    for (index, byte) in line.bytes().enumerate() {
        match (quote, byte) {
            (Some(current), value) if value == current => quote = None,
            (None, value @ (b'\'' | b'"')) => quote = Some(value),
            (None, b':') => return Some(index),
            _ => {}
        }
    }
    None
}

fn spring_devtools_offsets(path: &Path, source: &str) -> Vec<usize> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if file_name == "pom.xml" {
        if sxd_document::parser::parse(source).is_err() {
            return Vec::new();
        }
        let tags = start_tags(source);
        return tags
            .iter()
            .filter(|tag| {
                tag.name == "artifactId"
                    && element_text(source, tag) == Some("spring-boot-devtools")
                    && has_ancestor(source, &tags, tag, "dependency")
            })
            .map(|tag| tag.offset)
            .collect();
    }
    if path.extension().and_then(|value| value.to_str()) == Some("gradle") {
        let mut offsets = Vec::new();
        let mut base = 0usize;
        for line in source.split_inclusive('\n') {
            let code = line.split("//").next().unwrap_or_default();
            if let Some(relative) = code.find("org.springframework.boot:spring-boot-devtools") {
                offsets.push(base + relative);
            }
            base += line.len();
        }
        return offsets;
    }
    Vec::new()
}

fn build_config_offsets(check: JavaConfigCheck, path: &Path, source: &str) -> Vec<usize> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if path.extension().and_then(|value| value.to_str()) != Some("xml")
        || sxd_document::parser::parse(source).is_err()
    {
        return Vec::new();
    }
    let tags = start_tags(source);
    tags.iter()
        .filter(|tag| match check {
            JavaConfigCheck::BuildDynamicDependencyVersion => {
                file_name == "ivy.xml"
                    && tag.name == "dependency"
                    && tag.attribute("rev").is_some_and(is_dynamic_revision)
            }
            JavaConfigCheck::BuildExternalAntRepository => {
                file_name == "build.xml"
                    && tag.name == "get"
                    && tag.attribute("src").is_some_and(is_external_url)
            }
            JavaConfigCheck::BuildExternalIvyRepository => {
                matches!(file_name, "ivyconf.xml" | "ivysettings.xml")
                    && matches!(tag.name.as_str(), "ivy" | "artifact")
                    && tag.attribute("pattern").is_some_and(is_external_url)
            }
            JavaConfigCheck::BuildExternalMavenRepository => {
                matches!(file_name, "pom.xml" | "settings.xml")
                    && tag.name == "url"
                    && has_ancestor(source, &tags, tag, "repository")
                    && element_text(source, tag).is_some_and(is_external_url)
            }
            _ => false,
        })
        .map(|tag| tag.offset)
        .collect()
}

fn is_dynamic_revision(revision: &str) -> bool {
    let revision = revision.trim().to_ascii_lowercase();
    revision.starts_with("latest.")
        || revision.contains('+')
        || revision.starts_with('[')
        || revision.starts_with('(')
}

fn is_external_url(value: &str) -> bool {
    let value = value.trim();
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority.rsplit('@').next().unwrap_or_default();
    let host = if host_port.starts_with('[') {
        host_port
            .strip_prefix('[')
            .and_then(|value| value.split_once(']'))
            .map(|(host, _)| host)
            .unwrap_or(host_port)
    } else {
        host_port.split(':').next().unwrap_or_default()
    };
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return false;
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => !(ip.is_private() || ip.is_loopback() || ip.is_link_local()),
        Ok(IpAddr::V6(ip)) => {
            !(ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local())
        }
        Err(_) => !host.is_empty(),
    }
}

fn insecure_database_transport_offsets(path: &Path, source: &str) -> Vec<usize> {
    let extension = path.extension().and_then(|value| value.to_str());
    if !matches!(extension, Some("xml" | "properties" | "yml" | "yaml" | "conf" | "config")) {
        return Vec::new();
    }
    let mut offsets = Vec::new();
    if extension == Some("xml") {
        if sxd_document::parser::parse(source).is_err() {
            return Vec::new();
        }
        let tags = start_tags(source);
        for tag in &tags {
            let attribute_value = ["connectionString", "connection-string", "url", "jdbcUrl"]
                .iter()
                .find_map(|name| tag.attribute(name));
            let text_value = matches!(tag.name.as_str(), "url" | "connection-url" | "connectionString")
                .then(|| element_text(source, tag))
                .flatten();
            if attribute_value
                .or(text_value)
                .is_some_and(is_unencrypted_database_connection)
            {
                offsets.push(tag.offset);
            }
        }
    } else {
        let mut offset = 0usize;
        for line in source.split_inclusive('\n') {
            let trimmed = line.trim();
            if !trimmed.starts_with('#') && !trimmed.starts_with('!') {
                let value = trimmed
                    .split_once('=')
                    .or_else(|| trimmed.split_once(':'))
                    .map(|(_, value)| value.trim().trim_matches(['\'', '"']))
                    .unwrap_or(trimmed);
                if is_unencrypted_database_connection(value) {
                    offsets.push(offset + line.len() - line.trim_start().len());
                }
            }
            offset += line.len();
        }
    }
    offsets.sort_unstable();
    offsets.dedup();
    offsets
}

fn is_unencrypted_database_connection(value: &str) -> bool {
    let compact = value
        .to_ascii_lowercase()
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    let database = compact.contains("jdbc:")
        || compact.contains("datasource=")
        || compact.contains("datasource:")
        || compact.contains("server=")
        || compact.contains("mongodb://")
        || compact.contains("redis://");
    if !database {
        return false;
    }
    let secure = [
        "encrypt=true",
        "encrypt=yes",
        "ssl=true",
        "usessl=true",
        "requiressl=true",
        "sslmode=require",
        "sslmode=verify-ca",
        "sslmode=verify-full",
        "jdbc:oracle:thin:@tcps:",
        "mongodb+srv://",
        "rediss://",
    ]
    .iter()
    .any(|marker| compact.contains(marker));
    !secure
}

#[derive(Debug)]
struct DockerInstruction<'a> {
    name: &'a str,
    arguments: &'a str,
    offset: usize,
}

fn dockerfile_offsets(check: JavaConfigCheck, path: &Path, source: &str) -> Vec<usize> {
    if path.file_name().and_then(|name| name.to_str()) != Some("Dockerfile") {
        return Vec::new();
    }
    let instructions = docker_instructions(source);
    if check == JavaConfigCheck::DockerDefaultUserPrivilege {
        return match instructions
            .iter()
            .rev()
            .find(|instruction| instruction.name.eq_ignore_ascii_case("USER"))
        {
            None => vec![0],
            Some(instruction)
                if matches!(
                    instruction.arguments.trim().split([':', ' ']).next(),
                    Some("root" | "0")
                ) =>
            {
                vec![instruction.offset]
            }
            Some(_) => Vec::new(),
        };
    }
    instructions
        .iter()
        .filter(|instruction| match check {
            JavaConfigCheck::DockerPrivilegedContainer => instruction
                .arguments
                .split_ascii_whitespace()
                .any(|argument| {
                    argument == "--privileged" || argument.starts_with("--privileged=")
                }),
            JavaConfigCheck::DockerPrivilegedPort => {
                instruction.name.eq_ignore_ascii_case("EXPOSE")
                    && instruction.arguments.split_ascii_whitespace().any(|port| {
                        port.split('/')
                            .next()
                            .and_then(|value| value.parse::<u16>().ok())
                            .is_some_and(|port| (1..1024).contains(&port))
                    })
            }
            JavaConfigCheck::DockerSensitiveHostDirectory => {
                instruction.name.eq_ignore_ascii_case("VOLUME")
                    && docker_volume_paths(instruction.arguments).any(is_sensitive_container_path)
            }
            JavaConfigCheck::DockerSshService => {
                (instruction.name.eq_ignore_ascii_case("EXPOSE")
                    && instruction
                        .arguments
                        .split_ascii_whitespace()
                        .any(|port| port.split('/').next() == Some("22")))
                    || (instruction.name.eq_ignore_ascii_case("RUN")
                        && instruction.arguments.split_ascii_whitespace().any(|word| {
                            matches!(
                                word.trim_matches(|ch: char| !ch.is_ascii_alphanumeric()),
                                "sshd" | "openssh-server"
                            )
                        }))
            }
            _ => false,
        })
        .map(|instruction| instruction.offset)
        .collect()
}

fn docker_instructions(source: &str) -> Vec<DockerInstruction<'_>> {
    let mut instructions = Vec::new();
    let mut offset = 0usize;
    for line in source.split_inclusive('\n') {
        let leading = line.len() - line.trim_start().len();
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            let name_end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
            let name = &trimmed[..name_end];
            let arguments = trimmed[name_end..].trim();
            instructions.push(DockerInstruction {
                name,
                arguments,
                offset: offset + leading,
            });
        }
        offset += line.len();
    }
    instructions
}

fn docker_volume_paths(arguments: &str) -> impl Iterator<Item = &str> {
    arguments
        .trim_matches(['[', ']'])
        .split([',', ' ', '\t'])
        .map(|path| path.trim_matches(['\'', '"']))
        .filter(|path| !path.is_empty())
}

fn is_sensitive_container_path(path: &str) -> bool {
    path == "/"
        || ["/etc", "/proc", "/sys", "/dev", "/var/run", "/root"]
            .iter()
            .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
}
