#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FloatEqualityComparisonChecker : public Checker<check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* BOP, CheckerContext& C) const;

	private:
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void FloatEqualityComparisonChecker::checkPreStmt(const BinaryOperator* BOP, CheckerContext& C) const {
	if (BOP->getOpcode() == BO_EQ || BOP->getOpcode() == BO_NE) {
		const Expr* LHS = BOP->getLHS()->IgnoreParenImpCasts();
		const Expr* RHS = BOP->getRHS()->IgnoreParenImpCasts();

		if ((LHS->getType()->isFloatingType() || RHS->getType()->isFloatingType())) {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::FloatEqualityComparisonChecker, lang);

			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, Msg, BOP->getOperatorLoc(), C.getBugReporter());
		}
	}
}

void FloatEqualityComparisonChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "FloatEqualityComparisonChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "FloatEqualityComparisonChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFloatEqualityComparisonChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FloatEqualityComparisonChecker>();
}

bool ento::shouldRegisterFloatEqualityComparisonChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FloatEqualityComparisonChecker>("anzu.FloatEqualityComparisonChecker", "Prohibit equality comparisons between floating-point numbers", "");
}

#endif