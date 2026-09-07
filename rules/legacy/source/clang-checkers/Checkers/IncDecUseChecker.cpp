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
    class IncDecUseChecker : public Checker<check::PreStmt<BinaryOperator>, check::PreCall>{
        mutable std::unique_ptr<BugType> BT;

    public:
        void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const;
        void checkPreCall(const CallEvent& Call, CheckerContext& C) const;

    private:
        void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
    };
}


void IncDecUseChecker::checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const
{
    if (BO->isPtrMemOp() || BO->isAssignmentOp() || BO->isCommaOp()) {
        return;
    }

    const FunctionDecl* FD = nullptr;
    if (auto ADC = C.getCurrentAnalysisDeclContext()) {
        FD = dyn_cast<FunctionDecl>(ADC->getDecl());
    }
    auto LHS = BO->getLHS()->IgnoreParenImpCasts()->IgnoreCasts();
    if (auto UO = dyn_cast<UnaryOperator>(LHS)) {
        if (UO->isIncrementDecrementOp()) {
            reportBug(FD, UO->getOperatorLoc(), C.getBugReporter());
        }
    }
    auto RHS = BO->getRHS()->IgnoreParenImpCasts()->IgnoreCasts();
    if (auto UO = dyn_cast<UnaryOperator>(RHS)) {
        if (UO->isIncrementDecrementOp()) {
            reportBug(FD, UO->getOperatorLoc(), C.getBugReporter());
        }
    }
}

void IncDecUseChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
    const FunctionDecl* FD = nullptr;
    if (auto ADC = C.getCurrentAnalysisDeclContext()) {
        FD = dyn_cast<FunctionDecl>(ADC->getDecl());
    }

    for (int i = 0; i < Call.getNumArgs(); ++i) {
        if (auto E = Call.getArgExpr(i)) {
            E = E->IgnoreParenImpCasts()->IgnoreCasts();
            if (auto UO = dyn_cast<UnaryOperator>(E)) {
                if (UO->isIncrementDecrementOp()) {
                    reportBug(FD, UO->getOperatorLoc(), C.getBugReporter());
                }
            }
        }
    }
}

void IncDecUseChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT) {
        BT.reset(new BuiltinBug(
            this, "IncDecUseChecker"));
    }

    // Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::IncDecUseChecker, lang);        
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "IncDecUseChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerIncDecUseChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<IncDecUseChecker>();
}

bool ento::shouldRegisterIncDecUseChecker(const CheckerManager& mgr) {
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
    registry.addChecker<IncDecUseChecker>("anzu.IncDecUseChecker", "Be cautious when using the '++' or '--' operators.", "");
}

#endif