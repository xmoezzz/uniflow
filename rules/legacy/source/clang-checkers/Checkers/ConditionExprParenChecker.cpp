#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <unordered_set>
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
    class FindConditionExprVisitor
        : public RecursiveASTVisitor<FindConditionExprVisitor> {
        std::unordered_set<const Expr*> ExprList;

    public:
        const std::unordered_set<const Expr*>& getExprs() {
            return ExprList;
        }

    public:
        bool VisitConditionalOperator(const ConditionalOperator* CO) {
            if (auto Cond = CO->getCond()) {
                Cond = Cond->IgnoreCasts();
                if (isa<BinaryOperator>(Cond) || isa<ConditionalOperator>(Cond)) {
                    ExprList.insert(Cond);
                }
            }
            if (auto LHS = CO->getLHS()) {
                LHS = LHS->IgnoreCasts();
                if (isa<BinaryOperator>(LHS) || isa<ConditionalOperator>(LHS)) {
                    ExprList.insert(LHS);
                }
            }
            if (auto RHS = CO->getRHS()) {
                RHS = RHS->IgnoreCasts();
                if (isa<BinaryOperator>(RHS) || isa<ConditionalOperator>(RHS)) {
                    ExprList.insert(RHS);
                }
            }
            return true;
        }
    };

class ConditionExprParenChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BuiltinBug> BT;

public:
    void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
        BugReporter& BR) const;

  void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
};

void ConditionExprParenChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
    BugReporter& BR) const
{
    FindConditionExprVisitor Visitor;
    Visitor.TraverseDecl(const_cast<Decl*>(D));
    auto Exprs = Visitor.getExprs();
    for (auto E : Exprs) {
        reportBug(dyn_cast<FunctionDecl>(D), E->getBeginLoc(), BR);
    }
}

void ConditionExprParenChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
    if (Loc.isMacroID())
        return;

	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ConditionExprParenChecker"));
	}

	// Report the issue 
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::ConditionExprParenChecker, lang);    
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ConditionExprParenChecker"), DLoc);
    Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerConditionExprParenChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ConditionExprParenChecker>();
}

bool ento::shouldRegisterConditionExprParenChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ConditionExprParenChecker>("anzu.ConditionExprParenChecker", "The operands in a logical expression must be enclosed in parentheses.", "");
}

#endif