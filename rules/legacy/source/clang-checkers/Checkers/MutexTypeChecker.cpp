#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class MutexTypeChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void MutexTypeChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	const FunctionDecl* FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
	if (!FD)
		return;

	if (FD->getNameAsString() == "pthread_mutexattr_settype" && Call.getNumArgs() >= 2) {
		if (const Expr* MutexTypeArg = Call.getArgExpr(1)) {
			if (const DeclRefExpr* DRE = dyn_cast_or_null<DeclRefExpr>(MutexTypeArg->IgnoreParenCasts())) {
				const EnumConstantDecl* ECD = llvm::dyn_cast_or_null<EnumConstantDecl>(DRE->getDecl());
				if (ECD && ECD->getName() == "PTHREAD_MUTEX_NORMAL") {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}

					reportBug(FD, MutexTypeArg->getBeginLoc(), C.getBugReporter());
				}
			}
		}
	}
}

void MutexTypeChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "MutexTypeChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::MutexTypeChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "MutexTypeChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMutexTypeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MutexTypeChecker>();
}

bool ento::shouldRegisterMutexTypeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MutexTypeChecker>("anzu.MutexTypeChecker", "Checks for usage of PTHREAD_MUTEX_NORMAL.", "");
}

#endif