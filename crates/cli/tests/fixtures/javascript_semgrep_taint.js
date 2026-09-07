function load(name) { const moduleName = name; return require(moduleName); }
function compile(pattern) { return new RegExp(pattern); }
function safe() { require("./fixed.js"); RegExp("fixed"); }
function passwords(user, input) {
    const digest = crypto.createHash("md5").update(input).digest("hex");
    user.setPassword(digest);
    user.setPassword(crypto.createHash("sha256").update(input).digest("hex"));
}
function assign(target, input) {
    Object.assign(target, JSON.parse(input));
    Object.assign(target, JSON.parse('{"fixed": true}'));
}
