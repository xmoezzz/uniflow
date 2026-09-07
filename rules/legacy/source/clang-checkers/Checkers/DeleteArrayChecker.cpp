#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class DeleteArrayChecker : public Checker<check::PreStmt<CXXDeleteExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const CXXDeleteExpr* DE, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void DeleteArrayChecker::checkPreStmt(const CXXDeleteExpr* DE, CheckerContext& C) const {
	if (!DE->isArrayForm())
		return;

	const Expr* Arg = DE->getArgument();
	QualType ArgType = Arg->getType();
	auto State = C.getState();
	auto Val = State->getSVal(Arg, C.getLocationContext());
	auto Sym = Val.getAsSymbol();
	if (!Sym)
		return;

	auto OriginPT = Sym->getType().getCanonicalType()->getAs<PointerType>();
	auto CurPT = ArgType.getCanonicalType()->getAs<PointerType>();

	if (!OriginPT || !CurPT)
		return;

	if (OriginPT->getPointeeType() == CurPT->getPointeeType())
		return;

	if (!OriginPT->getPointeeType()->isRecordType())
		return;

	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}
	reportBug(FD, DE->getBeginLoc(), C.getBugReporter());
}

void DeleteArrayChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "DeleteArrayChecker"));

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::DeleteArrayChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "DeleteArrayChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDeleteArrayChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<DeleteArrayChecker>();
}

bool ento::shouldRegisterDeleteArrayChecker(const CheckerManager& mgr) {
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
	registry.addChecker<DeleteArrayChecker>(
		"anzu.DeleteArrayChecker",
		"Checks for deletion of arrays through pointers to the wrong type",
		"");
}

#endif
