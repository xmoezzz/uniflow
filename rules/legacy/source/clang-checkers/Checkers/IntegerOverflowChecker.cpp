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
	class IntegerOverflowChecker : public Checker< check::ASTDecl<VarDecl>, check::PreStmt<BinaryOperator> > {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const;
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		bool checkExpr(const QualType& LT, const Expr* Init, ASTContext& AST) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void IntegerOverflowChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const {
	if (auto Init = VD->getInit()) {
		if (!checkExpr(VD->getType(), Init, mgr.getASTContext()))
			return;
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::IntegerOverflowChecker, lang);

		reportBug(findFunctionDecl(VD), Msg, VD->getBeginLoc(), BR);
	}
}

void IntegerOverflowChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (B->getOpcode() != BO_Assign)
		return;

	if (!checkExpr(B->getLHS()->getType(), B->getRHS(), C.getASTContext()))
		return;
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::IntegerOverflowChecker, lang);

	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}
	reportBug(FD, Msg, B->getOperatorLoc(), C.getBugReporter());
}

bool IntegerOverflowChecker::checkExpr(const QualType& LT, const Expr* Init, ASTContext& AST) const {
	if (!LT->isIntegralOrEnumerationType())
		return false;

	if (!Init || !Init->IgnoreParenImpCasts()->getType()->isIntegralOrEnumerationType())
		return false;

	clang::Expr::EvalResult Result;
	if (!Init->IgnoreParenImpCasts()->EvaluateAsInt(Result, AST))
		return false;

	auto Value = Result.Val.getInt();
	llvm::APSInt MaxValue;
	if (LT->isSignedIntegerType()) {
		MaxValue = llvm::APSInt::getMaxValue(AST.getTypeSize(LT), false);
	}
	else {
		MaxValue = llvm::APSInt::getMaxValue(AST.getTypeSize(LT), true);
	}

	auto c = llvm::APSInt::compareValues(MaxValue, Value);
	if (c >= 0)
		return false;

	return true;
}

void IntegerOverflowChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "IntegerOverflowChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "IntegerOverflowChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerIntegerOverflowChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<IntegerOverflowChecker>();
}

bool ento::shouldRegisterIntegerOverflowChecker(const CheckerManager& mgr) {
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
	registry.addChecker<IntegerOverflowChecker>("anzu.IntegerOverflowChecker", "Assigned value is too large for the variable", "");
}

#endif