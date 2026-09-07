#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindExprVisitor
		: public RecursiveASTVisitor<FindExprVisitor> {
		std::list<const ReturnStmt*> ExprList;

	public:
		const std::list<const ReturnStmt*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitReturnStmt(const ReturnStmt* RS) {
			if (RS) {
				ExprList.push_back(RS);
			}
			return true;
		}
	};

	class ReturnTypeChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		void reportBug(const FunctionDecl* FD, const Stmt* S, QualType DefineType, QualType RealType, BugReporter& BR) const;
		bool isZero(const Expr* E) const;
		bool isValidAssign(ASTContext& AST, QualType LHSType, QualType RHSType, const Expr* RE) const;
	};
}

void ReturnTypeChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	if (Mgr.getASTContext().HasSyntaxErrors()) {
		return;
	}
	auto FD = dyn_cast<FunctionDecl>(D);
	if (!FD || !FD->isThisDeclarationADefinition() || !FD->hasBody()) {
		return;
	}

	auto DefineType = FD->getReturnType();
	if (!DefineType->isArithmeticType()) {
		return;
	}

	FindExprVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	AnalysisDeclContext* AC = Mgr.getAnalysisDeclContext(D);
	auto Exprs = Visitor.getExprs();
	for (auto RS : Exprs) {
		const Expr* RetE = RS->getRetValue();
		if (!RetE)
			continue;

		auto RealType = RetE->IgnoreParenImpCasts()->getType();
		if (isValidAssign(Mgr.getASTContext(), DefineType, RealType, RetE->IgnoreParenImpCasts()))
			continue;

		if (isZero(RetE->IgnoreParenImpCasts()))
			continue;

		reportBug(FD, RetE, DefineType, RealType, BR);
	}
}

bool ReturnTypeChecker::isValidAssign(ASTContext& AST, QualType LHSType, QualType RHSType, const Expr* RE) const {
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

bool ReturnTypeChecker::isZero(const Expr* E) const {
	if (!E) {
		return false;
	}

	E = E->IgnoreParenCasts();
	if (auto IL = dyn_cast<IntegerLiteral>(E)) {
		return IL->getValue() == 0;
	}

	return false;
}

void ReturnTypeChecker::reportBug(const FunctionDecl* FD, const Stmt* S, QualType DefineType, QualType RealType, BugReporter& BR) const {
	auto Loc1 = S->getBeginLoc();
	if (Loc1.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(this, "ReturnTypeChecker"));
	}
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::ReturnTypeChecker, lang);
	std::string rt = RealType.getAsString();
	std::string dt = DefineType.getAsString();
	std::string Msg = std::vformat(fmt, std::make_format_args(rt, dt));

	PathDiagnosticLocation Loc(Loc1, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ReturnTypeChecker"), Loc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerReturnTypeChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<ReturnTypeChecker>();
}

bool ento::shouldRegisterReturnTypeChecker(const CheckerManager& mgr) {
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
    registry.addChecker<ReturnTypeChecker>("anzu.ReturnTypeChecker", "Checks return type between function return type", "");
}

#endif

