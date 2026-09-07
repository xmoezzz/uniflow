#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <unordered_set>
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Decl.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class OverrideStdLibFunctionChecker : public Checker<check::ASTDecl<FunctionDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

		// 定义C语言标准库函数名称的集合
		std::unordered_set<std::string> StdLibFunctionNames = {
		  "printf", "scanf", "malloc", "free", "exit", "getchar", "putchar",
		  "fopen", "fclose", "memset", "memcpy", "strcmp", "strlen", "strcat",
		  "atoi", "atof", "sin", "cos", "tan", "sqrt", "pow", // TODO, add more
		};

	public:
		void checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void OverrideStdLibFunctionChecker::checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
		if (!D)
			return;

		// 获取函数名称
		IdentifierInfo* Ident = D->getIdentifier();
		if (!Ident)
			return;

		StringRef Name = Ident->getName();

		// 检查名称是否在标准库函数集合中
		if (StdLibFunctionNames.find(Name.str()) != StdLibFunctionNames.end()) {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::OverrideStdLibFunctionChecker, lang);
			reportBug(D, Msg, D->getBeginLoc(), BR);
		}
	}

	void OverrideStdLibFunctionChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "OverrideStdLibFunctionChecker"));
		}

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "OverrideStdLibFunctionChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerOverrideStdLibFunctionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<OverrideStdLibFunctionChecker>();
}

bool ento::shouldRegisterOverrideStdLibFunctionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<OverrideStdLibFunctionChecker>("anzu.OverrideStdLibFunctionChecker", "Disable Overriding a standard library function can lead to undefined behavior", "");
}

#endif
