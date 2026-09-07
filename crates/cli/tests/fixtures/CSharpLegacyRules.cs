class LegacyRules {
    [HttpPost]
    void Inspect(string text, XPathNavigator navigator, DataContext data,
                 ISession session, XQueryCompiler compiler, HtmlInputFile input,
                 FileUpload upload, AspNetWebSocketOptions options, Logger log,
                 HttpResponse response, Random random, HttpHeaders headers,
                 RSACryptoServiceProvider rsa) {
        var sql = new SqlDataAdapter(text, connection);
        navigator.Select(text);
        File.Create(text);
        Response.Redirect(text);
        var active = new SimpleQuery<Model>(text);
        var cookie = new Cookie("name", text);
        var posted = input.PostedFile;
        upload.SaveAs(text);
        HttpUtility.HtmlEncode(text);
        Razor.Parse(text, model);
        var inline = new InlineQuery(text);
        data.ExecuteCommand(text);
        log.Warn(text);
        session.CreateQuery(text);
        compiler.Compile(text);
        context.AcceptWebSocketRequest(handler, options);
        response.Headers.Remove("X-XSS-Protection");
        try { Work(); } catch(Exception ex) {
            Reponse.Write(ex.Message);
            Console.Write(ex.Message);
        }
        random.NextBytes(buffer);
        DES.Create();
        response.AddHeader("Access-Control-Allow-Origin", "*");
        headers.AddWithoutValidate("Access-Control-Allow-Origin", "*");
        response.EnableHeaderChecking = false;
        var formatter = new RSAPKCS1SignatureFormatter(key);
        var credentials = new ConnectionOptions("server", "user", null);
        var token = new UserNameSecurityToken("user", "");
        var padding = RSAEncryptionPadding.Pkcs1;
        var weakKey = new RSACryptoServiceProvider(1024);
        rsa.Encrypt(buffer, false);
    }
}
