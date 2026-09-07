#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
class UnnecessaryCastChecker : public Checker<check::PreStmt<CastExpr>> {
    mutable std::unique_ptr<BuiltinBug> BT;

public:
    void checkPreStmt(const CastExpr *CE, CheckerContext &C) const {
        if (C.getASTContext().HasSyntaxErrors()) {
            return;
        }
        
        if (dyn_cast<ImplicitCastExpr>(CE)) {
            return;
        }
        ASTContext &AC = C.getASTContext();
        QualType SourceType = CE->getSubExpr()->IgnoreParenImpCasts()->getType();
        QualType TargetType = CE->getType();
        
        if (SourceType == TargetType) {
            const FunctionDecl* FD = nullptr;
            if (auto ADC = C.getCurrentAnalysisDeclContext()) {
                FD = dyn_cast<FunctionDecl>(ADC->getDecl());
            }

            reportBug(FD, CE->getBeginLoc(), C.getBugReporter());
        }
  }

  void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
        if (Loc.isMacroID())
            return;

        if (!BT)
            BT.reset(new BuiltinBug(this, "UnnecessaryCastChecker"));

        // Report the issue
        auto ls = anzulocalization::LocaleSetting::getInstance();
        uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
        std::string Msg = ls->parseMsgs(anzulocalization::UnnecessaryCastChecker, lang);
        PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
        auto Report = std::make_unique<BasicBugReport>(
            *BT, Msg, createRuleExtData(1, "UnnecessaryCastChecker"), DLoc);
        Report->setDeclWithIssue(FD);
        BR.emitReport(std::move(Report));
    }

};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUnnecessaryCastChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<UnnecessaryCastChecker>();
}

bool ento::shouldRegisterUnnecessaryCastChecker(const CheckerManager& mgr) {
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
    registry.addChecker<UnnecessaryCastChecker>("anzu.UnnecessaryCastChecker", "", "");
}

#endif
