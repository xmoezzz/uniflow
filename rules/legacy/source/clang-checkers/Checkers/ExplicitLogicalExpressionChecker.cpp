#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindIfStmtCondVisitor
		: public RecursiveASTVisitor<FindIfStmtCondVisitor> {
		std::list<const Expr*> ExprList;

	public:
		const std::list<const Expr*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitIfStmt(const IfStmt* IS) {
			if (auto C = IS->getCond()) {
				ExprList.push_back(C);
			}
			return true;
		}
	};

	class ExplicitLogicalExpressionChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const {
			auto FD = dyn_cast<FunctionDecl>(D);
			FindIfStmtCondVisitor Visitor;
			Visitor.TraverseDecl(const_cast<Decl*>(D));
			auto Exprs = Visitor.getExprs();
			for (auto E : Exprs) {
				analyzeCond(FD, E, BR);
			}
		}

		void analyzeCond(const FunctionDecl* FD, const Expr* Condition, BugReporter& BR) const {
			if (Condition && isRepNegation(Condition)) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::ExplicitLogicalExpressionChecker, lang);
				reportBug(FD, Msg, Condition->getBeginLoc(), BR);
			}
		}

		bool isRepNegation(const Expr* E) const {
			// Check if the expression is a negation
			if (const UnaryOperator* UO = llvm::dyn_cast_or_null<UnaryOperator>(E->IgnoreParenImpCasts())) {
				if (UO->getOpcode() == UO_LNot) {
					if (auto BO = dyn_cast<BinaryOperator>(UO->getSubExpr()->IgnoreParenImpCasts())) {
						if (!BO->getBeginLoc().isMacroID() && BO->isComparisonOp()) {
							return true;
						}
					}
				}
			}
			return false;
		}

		bool isDoubleNegation(const Expr* E) const {
			// Check if the expression is a negation
			if (const UnaryOperator* UO = llvm::dyn_cast_or_null<UnaryOperator>(E->IgnoreParenImpCasts())) {
				if (UO->getOpcode() == UO_LNot) {
					// Check if the negated expression is also a negation
					return isa<UnaryOperator>(UO->getSubExpr()->IgnoreParenImpCasts()) &&
						cast<UnaryOperator>(UO->getSubExpr()->IgnoreParenImpCasts())->getOpcode() == UO_LNot;
				}
			}
			return false;
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "ExplicitLogicalExpressionChecker"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "ExplicitLogicalExpressionChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerExplicitLogicalExpressionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ExplicitLogicalExpressionChecker>();
}

bool ento::shouldRegisterExplicitLogicalExpressionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ExplicitLogicalExpressionChecker>("anzu.ExplicitLogicalExpressionChecker", "Suggests using explicit expressions for logical conditions", "");
}

#endif