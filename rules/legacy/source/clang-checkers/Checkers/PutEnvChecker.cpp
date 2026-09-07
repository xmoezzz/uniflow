#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class PutEnvChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void PutEnvChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	const FunctionDecl* FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
	if (!FD || FD->getNameAsString() != "putenv" || Call.getNumArgs() < 1)
		return;

	const Expr* Arg = Call.getArgExpr(0);
	if (!Arg) return;
	if (const DeclRefExpr* DRE = dyn_cast_or_null<DeclRefExpr>(Arg->IgnoreParenCasts())) {
		if (auto D = DRE->getDecl()) {
			if (const VarDecl* VD = llvm::dyn_cast_or_null<VarDecl>(D)) {
				if (VD->hasLocalStorage()) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}
					reportBug(FD, DRE->getBeginLoc(), C.getBugReporter());
				}
			}
		}
	}
}

void PutEnvChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "PutEnvChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::PutEnvChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "PutEnvChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPutEnvChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PutEnvChecker>();
}

bool ento::shouldRegisterPutEnvChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::C);
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
	registry.addChecker<PutEnvChecker>("anzu1.PutEnvChecker", "", "");
}

#endif