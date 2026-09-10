use uniflow_hir::{CallExpr, CallTarget, Expr, Item, Stmt};
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn call(imports: &str, parameters: &str, expression: &str) -> CallExpr {
    let source = format!("package demo;\n{imports}\nclass Chains {{ Object f({parameters}) {{ return {expression}; }} }}");
    let program = JavaParser::default()
        .parse_file("Chains.java", &source)
        .unwrap();
    let class = program.modules[0]
        .items
        .iter()
        .find_map(|item| {
            if let Item::Class(c) = item {
                Some(c)
            } else {
                None
            }
        })
        .unwrap();
    let Stmt::Return {
        value: Some(Expr::Call(call)),
        ..
    } = &class.methods[0].body.stmts[0]
    else {
        panic!("{class:#?}")
    };
    call.clone()
}

fn target(call: &CallExpr) -> &str {
    match &call.target {
        CallTarget::Named(name) => name,
        _ => panic!("{call:#?}"),
    }
}

#[test]
fn java_library_factory_receivers_are_calls_not_type_names() {
    for expression in [
        "java.lang.Runtime.getRuntime().exec(command)",
        "Runtime.getRuntime().exec(command)",
    ] {
        let outer = call("", "String command", expression);
        assert_eq!(target(&outer), "java.lang.Runtime.exec");
        let Some(Expr::Call(factory)) = outer.receiver.as_deref() else {
            panic!("factory receiver: {outer:#?}")
        };
        assert_eq!(target(factory), "java.lang.Runtime.getRuntime");
        assert!(factory.receiver.is_none());
    }
    let outer = call(
        "import static java.lang.Runtime.getRuntime;",
        "String command",
        "getRuntime().exec(command)",
    );
    assert_eq!(target(&outer), "java.lang.Runtime.exec");
}

#[test]
fn java_library_call_chains_preserve_external_return_types() {
    for owner in [
        "javax.servlet.ServletResponse",
        "javax.servlet.http.HttpServletResponse",
        "jakarta.servlet.ServletResponse",
        "jakarta.servlet.http.HttpServletResponse",
    ] {
        let outer = call(
            "",
            &format!("{owner} response"),
            "response.getWriter().println(\"text\")",
        );
        assert_eq!(target(&outer), "java.io.PrintWriter.println");
    }
    let outer = call(
        "",
        "javax.sql.DataSource data",
        "data.getConnection().createStatement().executeQuery(\"SELECT 1\")",
    );
    assert_eq!(target(&outer), "java.sql.Statement.executeQuery");
    assert!(
        matches!(outer.receiver.as_deref(), Some(Expr::Call(factory)) if target(factory) == "java.sql.Connection.createStatement")
    );

    for expression in [
        "data.getConnection().prepareStatement(\"SELECT 1\").setString(1, value)",
        "data.getConnection().prepareCall(\"call p()\").executeQuery()",
    ] {
        let outer = call("", "javax.sql.DataSource data, String value", expression);
        assert!(
            target(&outer).starts_with("java.sql.PreparedStatement.")
                || target(&outer).starts_with("java.sql.CallableStatement."),
            "{outer:#?}"
        );
    }

    let outer = call(
        "",
        "java.net.URL url",
        "url.openConnection().getInputStream().read()",
    );
    assert_eq!(target(&outer), "java.io.InputStream.read");
    let outer = call(
        "",
        "java.lang.ProcessBuilder builder",
        "builder.start().getOutputStream().write(1)",
    );
    assert_eq!(target(&outer), "java.io.OutputStream.write");
    for owner in [
        "javax.servlet.http.HttpServletRequest",
        "jakarta.servlet.http.HttpServletRequest",
    ] {
        let outer = call("", &format!("{owner} request, javax.servlet.ServletRequest servletRequest, javax.servlet.ServletResponse response"), "request.getRequestDispatcher(\"/view\").forward(servletRequest, response)");
        assert!(
            target(&outer).ends_with(".RequestDispatcher.forward"),
            "{outer:#?}"
        );
    }
}

#[test]
fn java_script_xpath_and_document_factories_preserve_receiver_types() {
    for expression in [
        "engines.getEngineByName(\"js\").eval(value)",
        "engines.getEngineByExtension(\"js\").eval(value)",
        "engines.getEngineByMimeType(\"text/javascript\").eval(value)",
    ] {
        assert_eq!(
            target(&call(
                "",
                "javax.script.ScriptEngineManager engines, String value",
                expression
            )),
            "javax.script.ScriptEngine.eval"
        );
    }
    assert_eq!(
        target(&call(
            "",
            "String value",
            "javax.xml.xpath.XPathFactory.newInstance().newXPath().compile(value)"
        )),
        "javax.xml.xpath.XPath.compile"
    );
    assert_eq!(target(&call("", "String value", "javax.xml.xpath.XPathFactory.newDefaultInstance().newXPath().compile(value).evaluate(value)")), "javax.xml.xpath.XPathExpression.evaluate");
    assert_eq!(target(&call("", "String value", "javax.xml.parsers.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(value)")), "javax.xml.parsers.DocumentBuilder.parse");
    assert_eq!(target(&call("", "String value", "javax.xml.parsers.DocumentBuilderFactory.newDefaultInstance().newDocumentBuilder().parse(value).getDocumentElement()")), "org.w3c.dom.Document.getDocumentElement");
    for (parameters, expression, forbidden) in [
        (
            "custom.ScriptEngineManager engines, String value",
            "engines.getEngineByName(\"js\").eval(value)",
            "javax.script.ScriptEngine.eval",
        ),
        (
            "javax.script.ScriptEngineManager engines, String value",
            "engines.getEngineByName().eval(value)",
            "javax.script.ScriptEngine.eval",
        ),
        (
            "String value",
            "javax.xml.xpath.XPathFactory.newInstance(1, 2).newXPath().compile(value)",
            "javax.xml.xpath.XPath.compile",
        ),
        (
            "String value",
            "custom.DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(value)",
            "javax.xml.parsers.DocumentBuilder.parse",
        ),
    ] {
        assert_ne!(target(&call("", parameters, expression)), forbidden);
    }
}

#[test]
fn java_path_factories_and_safe_filename_projection_preserve_path_type() {
    assert_eq!(
        target(&call(
            "",
            "String value",
            "java.nio.file.Paths.get(value).getFileName().toFile()",
        )),
        "java.nio.file.Path.toFile"
    );
    assert_eq!(
        target(&call(
            "",
            "String value",
            "java.nio.file.Paths.get(value, \"child\").getFileName()",
        )),
        "java.nio.file.Path.getFileName"
    );
    assert_ne!(
        target(&call("", "", "java.nio.file.Paths.get().getFileName()")),
        "java.nio.file.Path.getFileName"
    );
    assert_ne!(
        target(&call(
            "",
            "String value",
            "custom.Paths.get(value).getFileName()",
        )),
        "java.nio.file.Path.getFileName"
    );
}

#[test]
fn java_library_signatures_do_not_match_custom_owners_or_wrong_arities() {
    assert_ne!(
        target(&call(
            "",
            "custom.Response response",
            "response.getWriter().println(\"text\")"
        )),
        "java.io.PrintWriter.println"
    );
    assert_ne!(
        target(&call(
            "",
            "javax.servlet.http.HttpServletResponse response",
            "response.getWriter(1).println(\"text\")"
        )),
        "java.io.PrintWriter.println"
    );
    assert_ne!(
        target(&call(
            "",
            "java.sql.Connection connection",
            "connection.prepareStatement().executeQuery()"
        )),
        "java.sql.PreparedStatement.executeQuery"
    );
    assert_ne!(
        target(&call(
            "",
            "custom.URL url",
            "url.openConnection().getInputStream()"
        )),
        "java.net.URLConnection.getInputStream"
    );
    let outer = call(
        "import custom.Runtime;",
        "String command",
        "Runtime.getRuntime().exec(command)",
    );
    assert_ne!(target(&outer), "java.lang.Runtime.exec");
    let outer = call(
        "",
        "custom.Service Runtime",
        "Runtime.getRuntime().exec(\"safe\")",
    );
    assert_ne!(target(&outer), "java.lang.Runtime.exec");
    let Some(Expr::Call(factory)) = outer.receiver.as_deref() else {
        panic!("{outer:#?}")
    };
    assert!(factory.receiver.is_some());
}
