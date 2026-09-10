use std::{collections::HashMap, sync::OnceLock};
use uniflow_baseline::{builtin_security_pack, BaselinePack};
use uniflow_lang_java::JavaParser;
use uniflow_parser_core::SourceParser;

fn check(rule: &str, source: &str, expected: usize) {
    static PACK: OnceLock<BaselinePack> = OnceLock::new();
    let mut pack = PACK
        .get_or_init(|| builtin_security_pack().unwrap())
        .clone();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1, "missing {rule}");
    let hir = JavaParser::default()
        .parse_file("Resource.java", source)
        .unwrap();
    let findings = pack.scan_hir(
        &hir,
        &HashMap::from([("Resource.java".into(), source.into())]),
    );
    assert_eq!(findings.len(), expected, "{rule}: {source}\n{findings:#?}");
}

#[test]
fn migrated_java_resource_release_rules() {
    for (rule, ty) in [
        ("LEGACY-JAVA-AST-unreleased-db-resource", "Connection"),
        ("LEGACY-JAVA-AST-unreleased-file", "ZipFile"),
        ("LEGACY-JAVA-AST-unreleased-socket", "Socket"),
        ("LEGACY-JAVA-AST-unreleased-stream", "BufferedReader"),
    ] {
        check(
            rule,
            &format!("class A {{ void f() {{ {ty} resource=new {ty}(); use(resource); }} }}"),
            1,
        );
        check(
            rule,
            &format!("class A {{ void f() {{ {ty} resource=null; }} }}"),
            0,
        );
        check(
            rule,
            &format!("class A {{ void f() {{ {ty} resource=new {ty}(); resource.close(); }} }}"),
            0,
        );
        check(rule, &format!("class A {{ void f() {{ {ty} resource=new {ty}(); try {{ use(resource); }} finally {{ resource.close(); }} }} }}"), 0);
        check(rule, &format!("class A {{ void f() {{ {ty} resource=new {ty}(); try {{ resource.close(); }} catch(Exception e) {{ recover(); }} }} }}"), 1);
        check(
            rule,
            &format!("class A {{ void f({ty} resource) {{ resource=open(); }} }}"),
            1,
        );
        check(
            rule,
            &format!("class A {{ void f() {{ Object resource=new Object(); }} }}"),
            0,
        );
        check(rule, &format!("class A {{ void f() {{ {ty} resource=new {ty}(); Runnable r=() -> resource.close(); }} }}"), 1);
    }
    check("LEGACY-JAVA-AST-unreleased-db-resource",
        "class A { void f() { ResultSet result=open(); PreparedStatement statement=prepare(); result.close(); } }", 1);
    check("LEGACY-JAVA-AST-unreleased-stream",
        "class A { void f() { InputStreamReader input=open(); try { work(); } catch(Exception e) { input.close(); } } }", 1);
}

#[test]
fn android_resources_require_release_or_close_on_the_main_path() {
    for (rule, ty, release) in [
        (
            "LEGACY-JAVA-RULEMAP-unreleased-android-camera",
            "android.hardware.Camera",
            "release",
        ),
        (
            "LEGACY-JAVA-RULEMAP-unreleased-android-media",
            "android.media.MediaPlayer",
            "release",
        ),
        (
            "LEGACY-JAVA-RULEMAP-unreleased-android-sqlite",
            "android.database.sqlite.SQLiteDatabase",
            "close",
        ),
    ] {
        check(
            rule,
            &format!("class A {{ void f() {{ {ty} resource=open(); use(resource); }} }}"),
            1,
        );
        check(
            rule,
            &format!("class A {{ void f() {{ {ty} resource=open(); resource.{release}(); }} }}"),
            0,
        );
        check(rule, &format!("class A {{ void f() {{ {ty} resource=open(); try {{ use(resource); }} finally {{ resource.{release}(); }} }} }}"), 0);
        check(
            rule,
            "class A { void f() { Object resource=open(); use(resource); } }",
            0,
        );
    }
}

#[test]
fn android_resources_are_reported_when_used_after_release() {
    check(
        "LEGACY-JAVA-RULEMAP-use-released-camera",
        "class A { void f(Camera camera) { camera.release(); camera.startPreview(); } }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-use-released-camera",
        "class A { void f(Camera camera) { camera.startPreview(); camera.release(); } }",
        0,
    );
    check(
        "LEGACY-JAVA-RULEMAP-use-released-media",
        "class A { void f(MediaPlayer player) { player.release(); player.start(); } }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-use-released-media",
        "class A { void f(MediaPlayer player) { player.start(); player.release(); } }",
        0,
    );
    check("LEGACY-JAVA-RULEMAP-use-closed-sqlite", "class A { void f(SQLiteDatabase database) { database.close(); database.query(\"users\"); } }", 1);
    check("LEGACY-JAVA-RULEMAP-use-closed-sqlite", "class A { void f(SQLiteDatabase database) { database.query(\"users\"); database.close(); } }", 0);
    check(
        "LEGACY-JAVA-RULEMAP-use-recycled-bitmap",
        "class A { void f(Bitmap bitmap) { bitmap.recycle(); bitmap.getWidth(); } }",
        1,
    );
    check(
        "LEGACY-JAVA-RULEMAP-use-recycled-bitmap",
        "class A { void f(Bitmap bitmap) { bitmap.getWidth(); bitmap.recycle(); } }",
        0,
    );
}

#[test]
fn android_wakelock_requires_release() {
    let rule = "LEGACY-JAVA-RULEMAP-unreleased-wakelock";
    check(rule, "class A { void f(PowerManager manager) { PowerManager.WakeLock lock = manager.newWakeLock(1, \"sync\"); lock.acquire(); work(); } }", 1);
    check(rule, "class A { void f(PowerManager manager) { PowerManager.WakeLock lock = manager.newWakeLock(1, \"sync\"); try { lock.acquire(); work(); } finally { lock.release(); } } }", 0);
}

#[test]
fn explicit_lock_lifecycle_tracks_symbol_identity_and_balance() {
    let acquired = "LEGACY-JAVA-RULEMAP-lock-acquired-twice";
    check(acquired, "class A { void f(java.util.concurrent.locks.ReentrantLock lock) { lock.lock(); lock.lock(); lock.unlock(); lock.unlock(); } }", 1);
    check(acquired, "class A { void f(java.util.concurrent.locks.ReentrantLock one, java.util.concurrent.locks.ReentrantLock two) { one.lock(); two.lock(); one.unlock(); two.unlock(); } }", 0);

    let released = "LEGACY-JAVA-RULEMAP-lock-released-twice";
    check(released, "class A { void f(java.util.concurrent.locks.ReentrantLock lock) { lock.lock(); lock.unlock(); lock.unlock(); } }", 1);
    check(released, "class A { void f(java.util.concurrent.locks.ReentrantLock lock) { lock.lock(); lock.unlock(); } }", 0);

    let unreleased = "LEGACY-JAVA-RULEMAP-unreleased-explicit-lock";
    check(unreleased, "class A { void f(java.util.concurrent.locks.ReentrantLock lock) { lock.lock(); work(); } }", 1);
    check(unreleased, "class A { void f(java.util.concurrent.locks.ReentrantLock lock) { lock.lock(); try { work(); } finally { lock.unlock(); } } }", 0);
}

#[test]
fn thread_sleep_is_reported_only_while_an_explicit_lock_is_held() {
    let rule = "LEGACY-JAVA-RULEMAP-sleep-while-lock-held";
    check(rule, "class A { void f(java.util.concurrent.locks.ReentrantLock lock) { lock.lock(); Thread.sleep(10); lock.unlock(); } }", 1);
    check(rule, "class A { void f(java.util.concurrent.locks.ReentrantLock lock) { Thread.sleep(10); lock.lock(); work(); lock.unlock(); } }", 0);
    check(rule, "class A { void f(java.util.concurrent.locks.ReentrantLock lock) { lock.lock(); sleeper.sleep(10); lock.unlock(); } }", 0);
}

#[test]
fn temporary_files_are_tracked_through_delete_and_directory_conversion() {
    let leak = "LEGACY-JAVA-RULEMAP-temporary-file-not-deleted";
    check(
        leak,
        "class A { void f() { File temp=File.createTempFile(\"job\", \".tmp\"); use(temp); } }",
        1,
    );
    check(leak, "class A { void f() { File temp=File.createTempFile(\"job\", \".tmp\"); try { use(temp); } finally { temp.delete(); } } }", 0);

    let directory = "LEGACY-JAVA-RULEMAP-temporary-file-directory-race";
    check(directory, "class A { void f() { File temp=File.createTempFile(\"job\", \".tmp\"); temp.delete(); temp.mkdir(); } }", 1);
    check(
        directory,
        "class A { void f() { Path temp=Files.createTempDirectory(\"job\"); use(temp); } }",
        0,
    );
    check(
        directory,
        "class A { void f(File directory) { directory.mkdir(); } }",
        0,
    );
}

#[test]
fn null_safety_uses_path_refinement_and_known_nullable_apis() {
    let definite = "LEGACY-JAVA-RULEMAP-definite-null-dereference";
    check(
        definite,
        "class A { void f() { Data data=null; data.setId(1); } }",
        1,
    );
    check(
        definite,
        "class A { void f() { Data data=null; if (data != null) { data.setId(1); } } }",
        0,
    );
    check(
        definite,
        "class A { void f() { Data data=new Data(); data.setId(1); } }",
        0,
    );

    let nullable = "LEGACY-JAVA-RULEMAP-unchecked-nullable-return";
    check(nullable, "class A { void f() { String data=System.getenv(\"ADD\"); data.equalsIgnoreCase(\"x\"); } }", 1);
    check(nullable, "class A { void f() { String data=System.getenv(\"ADD\"); if (data != null) { data.equalsIgnoreCase(\"x\"); } } }", 0);
    check(
        nullable,
        "class A { void f() { String data=normalize(\"x\"); data.equalsIgnoreCase(\"x\"); } }",
        0,
    );

    let redundant = "LEGACY-JAVA-RULEMAP-redundant-null-check";
    check(
        redundant,
        "class A { void f(String data) { data.length(); if (data != null) { use(data); } } }",
        1,
    );
    check(
        redundant,
        "class A { void f() { String data=new String(); if (data == null) { fail(); } } }",
        1,
    );
    check(
        redundant,
        "class A { void f(String data) { if (data != null) { use(data); } } }",
        0,
    );
}

#[test]
fn numeric_casts_distinguish_narrowing_from_precision_loss() {
    let narrowing = "LEGACY-JAVA-RULEMAP-numeric-narrowing-cast";
    check(
        narrowing,
        "class A { int f(long value) { return (int) value; } }",
        1,
    );
    check(
        narrowing,
        "class A { float f(double value) { return (float) value; } }",
        1,
    );
    check(
        narrowing,
        "class A { long f(int value) { return (long) value; } }",
        0,
    );

    let floating = "LEGACY-JAVA-RULEMAP-integer-to-floating-precision-loss";
    check(
        floating,
        "class A { float f(int value) { return (float) value; } }",
        1,
    );
    check(
        floating,
        "class A { double f(long value) { return (double) value; } }",
        1,
    );
    check(
        floating,
        "class A { double f(int value) { return (double) value; } }",
        0,
    );
}

#[test]
fn enhanced_for_iteration_variables_are_not_reassigned() {
    let rule = "LEGACY-JAVA-RULEMAP-enhanced-for-item-reassigned";
    check(
        rule,
        "class A { void f(java.util.List<Item> items) { for (Item item : items) { item = next(item); use(item); } } }",
        1,
    );
    check(
        rule,
        "class A { void f(java.util.List<Item> items) { for (Item item : items) { if (replace(item)) { item = next(item); } } } }",
        1,
    );
    check(
        rule,
        "class A { void f(java.util.List<Item> items) { for (Item item : items) { item.process(); } } }",
        0,
    );
    check(
        rule,
        "class A { void f(java.util.List<Item> items) { Item current=null; for (Item item : items) { current = item; } } }",
        0,
    );
}

#[test]
fn external_process_buffers_are_drained_before_waiting() {
    let rule = "LEGACY-JAVA-RULEMAP-process-io-buffer-deadlock";
    check(
        rule,
        "class A { void f(Runtime runtime) { Process process=runtime.exec(command); process.waitFor(); } }",
        1,
    );
    check(
        rule,
        "class A { void f(Runtime runtime) { Process process=runtime.exec(command); process.getInputStream().readAllBytes(); process.getErrorStream().readAllBytes(); process.waitFor(); } }",
        0,
    );
    check(
        rule,
        "class A { void f() { ProcessBuilder builder=new ProcessBuilder(command); builder.redirectErrorStream(true); Process process=builder.start(); process.getInputStream().transferTo(System.out); process.waitFor(); } }",
        0,
    );
    check(
        rule,
        "class A { void f() { ProcessBuilder builder=new ProcessBuilder(command); builder.inheritIO(); Process process=builder.start(); process.waitFor(); } }",
        0,
    );
    check(
        rule,
        "class A { void f(Runtime runtime) { Process process=runtime.exec(command); InputStream output=process.getInputStream(); output.read(); process.waitFor(); } }",
        1,
    );
}

#[test]
fn expression_evaluation_does_not_access_a_symbol_after_writing_it() {
    let rule = "LEGACY-JAVA-RULEMAP-expression-access-after-write";
    check(
        rule,
        "class A { int f(int index) { return index++ + index; } }",
        1,
    );
    check(
        rule,
        "class A { int f(int index) { return (index = 4) + index; } }",
        1,
    );
    check(
        rule,
        "class A { int f(int index) { return index + 1; } }",
        0,
    );
    check(
        rule,
        "class A { int f(int index) { index++; return index; } }",
        0,
    );
}

#[test]
fn security_exceptions_use_resilient_structured_logging() {
    let rule = "LEGACY-JAVA-RULEMAP-unsafe-security-exception-logging";
    check(
        rule,
        "class A { void f() { try { secured(); } catch (SecurityException error) { System.err.println(error); recover(); } } }",
        1,
    );
    check(
        rule,
        "class A { void f() { try { secured(); } catch (java.security.AccessControlException error) { error.printStackTrace(); } } }",
        1,
    );
    check(
        rule,
        "class A { void f() { try { secured(); } catch (SecurityException error) { logger.log(Level.SEVERE, \"security failure\", error); recover(); } } }",
        0,
    );
    check(
        rule,
        "class A { void f() { try { secured(); } catch (Exception error) { System.err.println(error); } } }",
        0,
    );
}

#[test]
fn cryptographic_terminal_operations_require_input_updates() {
    let hash = "LEGACY-JAVA-RULEMAP-hash-missing-update";
    check(hash, "class A { byte[] f(MessageDigest digest) { return digest.digest(); } }", 1);
    check(hash, "class A { byte[] f(MessageDigest digest, byte[] input) { digest.update(input); return digest.digest(); } }", 0);
    check(hash, "class A { byte[] f(MessageDigest digest, byte[] input) { return digest.digest(input); } }", 0);

    let signature = "LEGACY-JAVA-RULEMAP-signature-missing-update";
    check(signature, "class A { byte[] f(Signature signature, PrivateKey key) { signature.initSign(key); return signature.sign(); } }", 1);
    check(signature, "class A { byte[] f(Signature signature, PrivateKey key, byte[] input) { signature.initSign(key); signature.update(input); return signature.sign(); } }", 0);
    check(signature, "class A { byte[] f(OtherSignature signature) { return signature.sign(); } }", 0);
}

#[test]
fn android_permission_callbacks_do_not_force_grants() {
    let rule = "LEGACY-JAVA-RULEMAP-geolocation-permission-override";
    check(rule, "class Client { void prompt(String origin, GeolocationPermissions.Callback callback) { callback.invoke(origin, true, false); } }", 1);
    check(rule, "class Client { void prompt(String origin, GeolocationPermissions.Callback callback, boolean granted) { callback.invoke(origin, granted, false); } }", 0);
    check(rule, "class Client { void prompt(String origin, OtherCallback callback) { callback.invoke(origin, true, false); } }", 0);
}

#[test]
fn protected_android_apis_are_checked_against_the_project_manifest() {
    let rule = "LEGACY-JAVA-RULEMAP-missing-send-sms-permission";
    let source = "class Sms { void send(SmsManager manager, String number, String text) { manager.sendTextMessage(number, null, text, null, null); } }";
    let mut pack = builtin_security_pack().unwrap();
    pack.rules.retain(|candidate| candidate.id == rule);
    assert_eq!(pack.rules.len(), 1);
    let hir = JavaParser::default().parse_file("Sms.java", source).unwrap();
    let missing = pack.scan_hir(
        &hir,
        &HashMap::from([("Sms.java".into(), source.into())]),
    );
    assert_eq!(missing.len(), 1, "{missing:#?}");
    let declared = pack.scan_hir(
        &hir,
        &HashMap::from([
            ("Sms.java".into(), source.into()),
            (
                "app/src/main/AndroidManifest.xml".into(),
                "<manifest><uses-permission android:name=\"android.permission.SEND_SMS\"/></manifest>".into(),
            ),
        ]),
    );
    assert_eq!(declared.len(), 0, "{declared:#?}");
}
