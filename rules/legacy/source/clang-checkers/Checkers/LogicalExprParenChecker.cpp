#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FindLogicExprVisitor
		: public RecursiveASTVisitor<FindLogicExprVisitor> {
		std::list<const BinaryOperator*> ExprList;

	public:
		const std::list<const BinaryOperator*>& getExprs() {
			return ExprList;
		}

	public:
		explicit FindLogicExprVisitor() {}

		bool VisitBinaryOperator(const BinaryOperator* B) {
			if (B->isLogicalOp()) {
				ExprList.push_back(B);
			}
			return true;
		}
	};

	class LogicalExprParenChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
		void checkLogicExpr(const FunctionDecl* FD, const BinaryOperator* BO, AnalysisManager& Mgr,
			BugReporter& BR) const;
		void reportBug(const FunctionDecl* FD, const Expr* E, AnalysisManager& Mgr,
			BugReporter& BR) const;
	};

	void LogicalExprParenChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
		BugReporter& BR) const
	{
		auto FD = dyn_cast<FunctionDecl>(D);
		FindLogicExprVisitor Visitor;
		Visitor.TraverseDecl(const_cast<Decl*>(D));
		auto Exprs = Visitor.getExprs();
		for (auto B : Exprs) {
			checkLogicExpr(FD, B, Mgr, BR);
		}
	}

	void LogicalExprParenChecker::checkLogicExpr(const FunctionDecl* FD, const BinaryOperator* BO, AnalysisManager& Mgr,
		BugReporter& BR) const {
		if (!BO)
			return;

		if (!BO->isLogicalOp())
			return;

		const Expr* LHS = BO->getLHS()->IgnoreImpCasts();
		if (auto BO_LHS = dyn_cast<BinaryOperator>(LHS)) {
			if (BO_LHS->isLogicalOp()) {
				reportBug(FD, LHS, Mgr, BR);
			}
		}
		const Expr* RHS = BO->getRHS()->IgnoreImpCasts();
		if (auto BO_RHS = dyn_cast<BinaryOperator>(RHS)) {
			if (BO_RHS->isLogicalOp()) {
				reportBug(FD, RHS, Mgr, BR);
			}
		}
	}

	void LogicalExprParenChecker::reportBug(const FunctionDecl* FD, const Expr* E, AnalysisManager& Mgr,
		BugReporter& BR) const {
		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "LogicalExprParenChecker"));
		}

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::LogicalExprParenChecker, lang);        
		PathDiagnosticLocation Loc(E->getBeginLoc(), Mgr.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "LogicalExprParenChecker"), Loc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerLogicalExprParenChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<LogicalExprParenChecker>();
}

bool ento::shouldRegisterLogicalExprParenChecker(const CheckerManager& mgr) {
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
	registry.addChecker<LogicalExprParenChecker>("anzu.LogicalExprParenChecker", "", "");
}

#endif