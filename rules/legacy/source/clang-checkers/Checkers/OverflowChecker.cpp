#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SymbolManager.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
    class OverflowChecker : public Checker< check::PreStmt<BinaryOperator> > {
        mutable std::unique_ptr<BuiltinBug> BT;

    public:
        void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;

    private:
        std::optional<llvm::APSInt> GetAPSInt(SVal Val) const;
        void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
    };
}
void OverflowChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
    if (!B->isAdditiveOp() && !B->isMultiplicativeOp())
        return;

    const Expr* LHS = B->getLHS();
    const Expr* RHS = B->getRHS();

    SVal LVal = C.getSVal(LHS);
    SVal RVal = C.getSVal(RHS);

    if (auto LInt = GetAPSInt(LVal))
        if (auto RInt = GetAPSInt(RVal)) {
            bool Overflow;
            if (B->isAdditiveOp()) {
                auto&& Val = LInt->sadd_ov(*RInt, Overflow);
            }
            else if (B->isMultiplicativeOp()) {
                auto&& Val = LInt->smul_ov(*RInt, Overflow);
            }

            if (Overflow) {
                auto ls = anzulocalization::LocaleSetting::getInstance();
                uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
                std::string Msg = ls->parseMsgs(anzulocalization::OverflowChecker, lang);
                const FunctionDecl* FD = nullptr;
                if (auto ADC = C.getCurrentAnalysisDeclContext()) {
                    FD = dyn_cast<FunctionDecl>(ADC->getDecl());
                }
                reportBug(FD, Msg, B->getOperatorLoc(), C.getBugReporter());
            }
        }
}

std::optional<llvm::APSInt> OverflowChecker::GetAPSInt(SVal Val) const
{
    if (Optional<NonLoc> NL = Val.getAs<NonLoc>()) {
        if (Optional<nonloc::ConcreteInt> CI = NL->getAs<nonloc::ConcreteInt>()) {
            return CI->getValue();
        }
    }
    return std::nullopt;
}

void OverflowChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT)
        BT.reset(new BuiltinBug(this, "OverflowChecker"));

    // Report the issue        
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "OverflowChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerOverflowChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<OverflowChecker>();
}

bool ento::shouldRegisterOverflowChecker(const CheckerManager& mgr) {
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
    registry.addChecker<OverflowChecker>("anzu.OverflowChecker", "Checks for integer overflows", "");
}

#endif