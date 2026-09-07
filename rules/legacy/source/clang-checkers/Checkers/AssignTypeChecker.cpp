#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class AssignTypeChecker : public Checker<check::ASTDecl<VarDecl>, check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;
	public:
		void checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const;
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		bool isValidAssign(ASTContext& AST, QualType LHSType, QualType RHSType, const Expr* RE) const;
		bool isZero(const Expr* E) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void AssignTypeChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const {
	if (mgr.getASTContext().HasSyntaxErrors()) {
		return;
	}

	if (auto Init = VD->getInit()) {
		QualType LHSType = VD->getType();
		QualType RHSType = Init->IgnoreParenImpCasts()->getType();

		if (isValidAssign(mgr.getASTContext(), LHSType, RHSType, Init))
			return;

		if (isZero(Init->IgnoreParenImpCasts()))
			return;
		
        auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::AssignTypeChecker, lang);
		reportBug(findFunctionDecl(VD), Msg, Init->getBeginLoc(), BR);
	}
}

void AssignTypeChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (C.getASTContext().HasSyntaxErrors()) {
		return;
	}

	if (B->getOpcode() != BO_Assign) {
		return;
	}
	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}
	const Expr* LHS = B->getLHS();
	const Expr* RHS = B->getRHS()->IgnoreParenImpCasts();

	QualType LHSType = LHS->getType();
	QualType RHSType = RHS->getType();

	if (isValidAssign(C.getASTContext(), LHSType, RHSType, RHS))
		return;

	if (isZero(RHS))
		return;

	reportBug(FD, "Prohibit assigning values to variables that are inconsistent with the type of the variable", B->getOperatorLoc(), C.getBugReporter());
}

bool AssignTypeChecker::isValidAssign(ASTContext& AST, QualType LHSType, QualType RHSType, const Expr* RE) const {
	if (!LHSType->isIntegralOrEnumerationType() && !LHSType->isFloatingType())
		return true;

	if (LHSType == RHSType)
		return true;

	if ((LHSType->isIntegralOrEnumerationType() ^ RHSType->isIntegralOrEnumerationType()) ||
		(LHSType->isFloatingType() ^ RHSType->isFloatingType())) {
		return false;
	}

	clang::Expr::EvalResult Result;
	if (RE->IgnoreParenImpCasts()->EvaluateAsInt(Result, AST)) {
		auto Value = Result.Val.getInt();
		llvm::APSInt MaxValue;
		if (LHSType->isSignedIntegerType()) {
			MaxValue = llvm::APSInt::getMaxValue(AST.getTypeSize(LHSType), false);
		}
		else {
			MaxValue = llvm::APSInt::getMaxValue(AST.getTypeSize(LHSType), true);
		}

		auto c = llvm::APSInt::compareValues(MaxValue, Value);
		if (c < 0)
			return false;
	}

	return true;
}

bool AssignTypeChecker::isZero(const Expr* E) const {
	if (!E) {
		return false;
	}

	E = E->IgnoreParenCasts();
	if (auto IL = dyn_cast<IntegerLiteral>(E)) {
		return IL->getValue() == 0;
	}

	return false;
}

void AssignTypeChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "AssignTypeChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "AssignTypeChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAssignTypeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<AssignTypeChecker>();
}

bool ento::shouldRegisterAssignTypeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<AssignTypeChecker>("anzu.AssignTypeChecker", "Prohibit assigning negative values to unsigned type variables", "");
}

#endif