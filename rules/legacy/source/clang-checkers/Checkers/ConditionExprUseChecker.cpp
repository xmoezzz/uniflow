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
        std::unordered_set<const ConditionalOperator*> ExprList;

    public:
        const std::unordered_set<const ConditionalOperator*>& getExprs() {
            return ExprList;
        }

    public:
        bool VisitUnaryOperator(const UnaryOperator* UO) {
            if (auto CO = dyn_cast<ConditionalOperator>(UO->getSubExpr()->IgnoreImpCasts())) {
                ExprList.insert(CO);
            }
            return true;
        }
        bool VisitBinaryOperator(const BinaryOperator* BO) {
            if (auto CO = dyn_cast<ConditionalOperator>(BO->getLHS()->IgnoreImpCasts())) {
                ExprList.insert(CO);
            }
            if (auto CO = dyn_cast<ConditionalOperator>(BO->getRHS()->IgnoreImpCasts())) {
                ExprList.insert(CO);
            }
            return true;
        }
        bool VisitConditionalOperator(const ConditionalOperator* CO) {
            if (!IsValidExpr(CO->getCond())) {
                ExprList.insert(CO);
            } else if (!IsValidExpr(CO->getTrueExpr())) {
                ExprList.insert(CO);
            } else if (!IsValidExpr(CO->getFalseExpr())) {
                ExprList.insert(CO);
            }

            return true;
        }

        bool IsValidExpr(const Expr* E) {
            if (E && isa<BinaryOperator>(E->IgnoreImpCasts())) {
                return false;
            }
            return true;
        }
    };

class ConditionExprUseChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BuiltinBug> BT;

public:
    void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
        BugReporter& BR) const;

  void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
};

void ConditionExprUseChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
    BugReporter& BR) const
{
    FindConditionExprVisitor Visitor;
    Visitor.TraverseDecl(const_cast<Decl*>(D));
    auto Exprs = Visitor.getExprs();
    for (auto CO : Exprs) {
        reportBug(dyn_cast<FunctionDecl>(D), CO->getBeginLoc(), BR);
    }
}

void ConditionExprUseChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ConditionExprUseChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::ConditionExprUseChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ConditionExprUseChecker"), DLoc);
    Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerConditionExprUseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ConditionExprUseChecker>();
}

bool ento::shouldRegisterConditionExprUseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ConditionExprUseChecker>("anzu.ConditionExprUseChecker", "Use ternary expressions with caution.", "");
}

#endif