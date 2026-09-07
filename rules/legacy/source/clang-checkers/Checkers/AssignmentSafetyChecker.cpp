#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/AST.h"
#include "clang/AST/ExprCXX.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

class AssignmentSafetyChecker : public Checker<check::PostStmt<CXXOperatorCallExpr>> {
    mutable std::unique_ptr<BuiltinBug> BT;

public:
    void checkPostStmt(const CXXOperatorCallExpr *OCE, CheckerContext &C) const;
    void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
};

}

void AssignmentSafetyChecker::checkPostStmt(const CXXOperatorCallExpr *OCE, CheckerContext &C) const {
    // Check if this is an assignment operator call
    if (OCE->getOperator() != OO_Equal)
        return;

    auto ls = anzulocalization::LocaleSetting::getInstance();
    uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
    std::string Msg = ls->parseMsgs(anzulocalization::AssignmentSafetyChecker, lang);

    for (const Expr *Arg : OCE->arguments()) {
        // Search for raw pointer copies in the arguments
        if (const UnaryOperator *UO = llvm::dyn_cast_or_null<UnaryOperator>(Arg->IgnoreParenImpCasts())) {
            if (UO->getOpcode() == UO_AddrOf) {
                if (UO->getSubExpr()->getType()->isPointerType()) {
                    const FunctionDecl* FD = nullptr;
                    if (auto ADC = C.getCurrentAnalysisDeclContext()) {
                        FD = dyn_cast<FunctionDecl>(ADC->getDecl());
                    }
                    reportBug(FD, Msg, UO->getOperatorLoc(), C.getBugReporter());
                }
            }
        }
    }
}

void AssignmentSafetyChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT)
        BT.reset(new BuiltinBug(this, "AssignmentSafetyChecker"));

    // Report the issue        
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "AssignmentSafetyChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAssignmentSafetyChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<AssignmentSafetyChecker>();
}

bool ento::shouldRegisterAssignmentSafetyChecker(const CheckerManager& mgr) {
    return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::CPP);
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
    registry.addChecker<AssignmentSafetyChecker>("anzu.AssignmentSafetyChecker", "", "");
}

#endif