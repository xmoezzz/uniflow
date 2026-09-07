#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include <clang/AST/ExprCXX.h>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class CStyleCastChecker : public Checker<check::PreStmt<CStyleCastExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const CStyleCastExpr* CE, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void CStyleCastChecker::checkPreStmt(const CStyleCastExpr* CE, CheckerContext& C) const {
	auto FilePath = C.getSourceManager().getFilename(CE->getBeginLoc());
	auto FileName = llvm::sys::path::filename(FilePath);
	auto ExtName = llvm::sys::path::extension(FileName);
	if (ExtName != ".cpp")
		return;

	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}

	reportBug(FD, CE->getBeginLoc(), C.getBugReporter());
}

void CStyleCastChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "CStyleCastChecker"));

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CStyleCastChecker, lang);
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CStyleCastChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCStyleCastChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CStyleCastChecker>();
}

bool ento::shouldRegisterCStyleCastChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::CPP);
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
	registry.addChecker<CStyleCastChecker>("anzu.CStyleCastChecker", "Avoid using C-style casts", "");
}

#endif
