#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <memory>
#include "../Utils.h"
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {
	class AssertAndAtexitChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BuiltinBug> BT;
		mutable bool HasAtexit = false;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void AssertAndAtexitChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
		auto CE = Call.getOriginExpr();
		if (!CE)
			return;

		const FunctionDecl* FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
		if (!FD)
			return;

		auto FName = FD->getQualifiedNameAsString();
		if (FName == "atexit" || FName == "at_quick_exit") {
			HasAtexit = true;
			return;
		}

		if (!HasAtexit)
			return;

		if (FName == "assert" || FName == "abort") {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, CE->getBeginLoc(), C.getBugReporter());
		}
	}

	void AssertAndAtexitChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "AssertAndAtexitChecker"));

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::AssertAndAtexitChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "AssertAndAtexitChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAssertAndAtexitChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<AssertAndAtexitChecker>();
}

bool ento::shouldRegisterAssertAndAtexitChecker(const CheckerManager& mgr) {
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
	registry.addChecker<AssertAndAtexitChecker>("anzu.AssertAndAtexitChecker", "", "");
}

#endif