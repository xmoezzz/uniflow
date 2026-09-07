#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/CheckerManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class SignedIntOddEvenChecker : public Checker< check::BranchCondition > {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkBranchCondition(const Stmt* Condition, CheckerContext& C) const;
		bool IsOddEvenCheck(const Expr* LHS, const Expr* RHS) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void SignedIntOddEvenChecker::checkBranchCondition(const Stmt* Condition, CheckerContext& C) const {
	auto E = dyn_cast<Expr>(Condition);
	if (!E)
		return;

	auto BO = dyn_cast<BinaryOperator>(E->IgnoreParenCasts());
	if (!BO)
		return;

	if (!BO->isEqualityOp())
		return;

	if (IsOddEvenCheck(BO->getLHS(), BO->getRHS()) || IsOddEvenCheck(BO->getRHS(), BO->getLHS())) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}

		reportBug(FD, Condition->getBeginLoc(), C.getBugReporter());
	}
}

bool SignedIntOddEvenChecker::IsOddEvenCheck(const Expr* LHS, const Expr* RHS) const {
	if (auto BO = dyn_cast<BinaryOperator>(LHS->IgnoreParenCasts())) {
		if (auto IL = dyn_cast<IntegerLiteral>(RHS->IgnoreParenCasts())) {
			if (IL->getValue() == 0 || IL->getValue() == 1) {
				if (BO->getOpcode() == BinaryOperatorKind::BO_And) {
					if (auto IL = dyn_cast<IntegerLiteral>(BO->getLHS()->IgnoreParenCasts())) {
						return IL->getValue() == 1 && !isa<IntegerLiteral>(BO->getRHS()->IgnoreParenCasts());
					}
					else if (auto IL = dyn_cast<IntegerLiteral>(BO->getRHS()->IgnoreParenCasts())) {
						return IL->getValue() == 1 && !isa<IntegerLiteral>(BO->getLHS()->IgnoreParenCasts());
					}
				}
			}
		}
	}

	return false;
}

void SignedIntOddEvenChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "SignedIntOddEvenChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::SignedIntOddEvenChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "SignedIntOddEvenChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSignedIntOddEvenChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SignedIntOddEvenChecker>();
}

bool ento::shouldRegisterSignedIntOddEvenChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SignedIntOddEvenChecker>("anzu.SignedIntOddEvenChecker", "", "");
}

#endif