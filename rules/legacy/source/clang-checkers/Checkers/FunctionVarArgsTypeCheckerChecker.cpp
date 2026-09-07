#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FunctionVarArgsTypeCheckerChecker : public Checker<check::ASTDecl<FunctionDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const FunctionDecl* D, BugReporter& BR) const;
	};
} // end anonymous namespace

void FunctionVarArgsTypeCheckerChecker::checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	// Ignore system header
	auto& SM = Mgr.getSourceManager();
	if (SM.isInSystemMacro(D->getLocation()) ||
		SM.isInSystemHeader(D->getLocation())) {
		return;
	}

	if (!D->isVariadic()) {
		return;
	}

	reportBug(D, BR);
}

void FunctionVarArgsTypeCheckerChecker::reportBug(const FunctionDecl* D, BugReporter& BR) const {
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "FunctionVarArgsTypeCheckerChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::FunctionVarArgsTypeCheckerChecker, lang);        
	PathDiagnosticLocation Loc(D->getBeginLoc(), BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "FunctionVarArgsTypeCheckerChecker"), Loc);
	Report->setDeclWithIssue(D);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFunctionVarArgsTypeCheckerChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FunctionVarArgsTypeCheckerChecker>();
}

bool ento::shouldRegisterFunctionVarArgsTypeCheckerChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FunctionVarArgsTypeCheckerChecker>("anzu.FunctionVarArgsTypeCheckerChecker", "Disallow defined variable function", "");
}

#endif