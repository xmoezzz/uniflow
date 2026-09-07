#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

#include <set>

using namespace clang;
using namespace clang::ento;

namespace {
	static std::set<std::string> Keywords = {
		// C keywords (also keywords in C++)
		"auto", "break", "case", "char", "const", "continue", "default", "do",
		"double", "else", "enum", "extern", "float", "for", "goto", "if",
		"inline", "int", "long", "register", "restrict", "return", "short",
		"signed", "sizeof", "static", "struct", "switch", "typedef", "union",
		"unsigned", "void", "volatile", "while",
		// C++-only keywords
		"alignas", "alignof", "and", "and_eq", "asm", "bitand", "bitor",
		"bool", "catch", "class", "compl", "constexpr", "const_cast",
		"delete", "dynamic_cast", "explicit", "export", "false", "friend",
		"mutable", "namespace", "new", "not", "not_eq", "nullptr", "operator",
		"or", "or_eq", "private", "protected", "public", "reinterpret_cast",
		"static_assert", "static_cast", "template", "this", "thread_local",
		"throw", "true", "try", "typeid", "typename", "using", "virtual", "wchar_t",
		"xor", "xor_eq"
	};

	class TypedefKeywordChecker : public Checker<check::ASTDecl<TypedefDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const TypedefDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void TypedefKeywordChecker::checkASTDecl(const TypedefDecl* TD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (TD) {
		auto Name = TD->getUnderlyingType().getAsString();
		if (Keywords.find(Name) != Keywords.end()) {

			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string fmt = ls->parseMsgs(anzulocalization::TypedefKeywordChecker, lang);
			std::string Msg = std::vformat(fmt, std::make_format_args(Name));

			reportBug(findFunctionDecl(TD), Msg, TD->getBeginLoc(), BR);
		}
	}
}

void TypedefKeywordChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "TypedefKeywordChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "TypedefKeywordChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerTypedefKeywordChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<TypedefKeywordChecker>();
}

bool ento::shouldRegisterTypedefKeywordChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::C | CheckerLanguage::CPP);
}

#else
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"

extern "C"
#ifdef _WINDOWS
_declspec(dllexport)
#else
__attribute__((visibility("default")))
#endif
const
char clang_analyzerAPIVersionString[] = CLANG_ANALYZER_API_VERSION_STRING;

extern "C"
#ifdef _WINDOWS
_declspec(dllexport)
#else
__attribute__((visibility("default")))
#endif
void clang_registerCheckers(CheckerRegistry & registry) {
	registry.addChecker<TypedefKeywordChecker>("anzu.TypedefKeywordChecker", "Prohibit redefining keywords in C or C++.", "");
}

#endif