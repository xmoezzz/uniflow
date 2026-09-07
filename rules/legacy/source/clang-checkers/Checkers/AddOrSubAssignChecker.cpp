#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
    class FindBinaryExprVisitor
        : public RecursiveASTVisitor<FindBinaryExprVisitor> {
        std::list<const BinaryOperator*> ExprList;

    public:
        const std::list<const BinaryOperator*>& getExprs() {
            return ExprList;
        }

    public:
        bool VisitBinaryOperator(const BinaryOperator* BO) {
            if (BO->getOpcode() == BO_AddAssign ||
                BO->getOpcode() == BO_SubAssign) {
                ExprList.push_back(BO);
            }
            return true;
        }
    };
    class AddOrSubAssignChecker : public Checker<check::ASTCodeBody> {
        mutable std::unique_ptr<BugType> BT;

    public:
        void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
            BugReporter& BR) const;

    private:
        void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
    };
}


void AddOrSubAssignChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
    BugReporter& BR) const
{
    FindBinaryExprVisitor Visitor;
    Visitor.TraverseDecl(const_cast<Decl*>(D));
    auto Exprs = Visitor.getExprs();
    for (auto BO : Exprs) {
        reportBug(dyn_cast<FunctionDecl>(D), BO->getOperatorLoc(), BR);
    }
}

void AddOrSubAssignChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;

    if (!BT) {
        BT.reset(new BuiltinBug(
            this, "AddOrSubAssignChecker"));
    }

    // Report the issue        
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto ls = anzulocalization::LocaleSetting::getInstance();
    uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string msg = ls->parseMsgs(anzulocalization::AddOrSubAssignChecker, lang);
    auto Report = std::make_unique<BasicBugReport>(
        *BT, msg, createRuleExtData(1, "AddOrSubAssignChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAddOrSubAssignChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<AddOrSubAssignChecker>();
}

bool ento::shouldRegisterAddOrSubAssignChecker(const CheckerManager& mgr) {
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
    registry.addChecker<AddOrSubAssignChecker>("anzu.AddOrSubAssignChecker", "Avoid using the '+=' or '-=' operators.", "");
}

#endif