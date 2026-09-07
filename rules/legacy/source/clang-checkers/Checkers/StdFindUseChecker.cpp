#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class StdFindUseChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void StdFindUseChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
		if (Call.getNumArgs() <= 2)
			return;

		auto D = Call.getDecl();
		if (!D)
			return;

		auto FD = dyn_cast<FunctionDecl>(D);
		if (!FD)
			return;

		auto Name = FD->getQualifiedNameAsString();
		if (Name != "std::find")
			return;

		auto MCE = ToMemberCallExpr(Call.getArgExpr(0));
		if (!MCE)
			return;

		auto ThisExpr = MCE->getImplicitObjectArgument();
		if (!ThisExpr)
			return;

		auto DRE = dyn_cast<DeclRefExpr>(ThisExpr->IgnoreParenCasts());
		if (!DRE)
			return;

		auto ValueD = DRE->getDecl();
		if (!ValueD)
			return;

		auto VD = dyn_cast<VarDecl>(ValueD);
		if (!VD)
			return;

		auto VName = GetTypeName(VD->getType());
		if (VName == "std::set") {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}

			reportBug(FD, MCE->getBeginLoc(), C.getBugReporter());
		}
	}

	void StdFindUseChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "StdFindUseChecker"));

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::StdFindUseChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "StdFindUseChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerStdFindUseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<StdFindUseChecker>();
}

bool ento::shouldRegisterStdFindUseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<StdFindUseChecker>("anzu.StdFindUseChecker", "", "");
}

#endif