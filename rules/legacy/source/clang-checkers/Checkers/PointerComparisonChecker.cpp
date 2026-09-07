#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
class PointerComparisonChecker : public Checker<check::PreStmt<BinaryOperator>> {
  mutable std::unique_ptr<BuiltinBug> BT;

public:
  void checkPreStmt(const BinaryOperator *BOP, CheckerContext &C) const;

private:
  void reportBug(const FunctionDecl* FD, std::string& Msg, const BinaryOperator* BOP, CheckerContext &C) const;
};
}

void PointerComparisonChecker::checkPreStmt(const BinaryOperator *BOP, CheckerContext &C) const {
  if (BOP->isRelationalOp()) {
    const Expr *LHS = BOP->getLHS()->IgnoreParenImpCasts();
    const Expr *RHS = BOP->getRHS()->IgnoreParenImpCasts();

    if ((LHS->getType()->isPointerType() && RHS->getType()->isPointerType())) {
        const FunctionDecl* FD = nullptr;
        if (auto ADC = C.getCurrentAnalysisDeclContext()) {
            FD = dyn_cast<FunctionDecl>(ADC->getDecl());
        }
      auto ls = anzulocalization::LocaleSetting::getInstance();
      uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
      std::string Msg = ls->parseMsgs(anzulocalization::PointerComparisonChecker, lang);
      reportBug(FD, Msg, BOP, C);
    }
  }
}

void PointerComparisonChecker::reportBug(const FunctionDecl* FD, std::string &Msg, const BinaryOperator* BOP, CheckerContext &C) const {
  auto Loc1 = BOP->getOperatorLoc();
  if (Loc1.isMacroID())
    return;

  if (!BT)
    BT.reset(new BuiltinBug(this, "PointerComparisonChecker"));

  // Report the issue        
  PathDiagnosticLocation Loc(Loc1, C.getSourceManager());
  auto Report = std::make_unique<BasicBugReport>(
      *BT, Msg, createRuleExtData(1, "PointerComparisonChecker"), Loc);
  Report->setDeclWithIssue(FD);
  C.getBugReporter().emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPointerComparisonChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<PointerComparisonChecker>();
}

bool ento::shouldRegisterPointerComparisonChecker(const CheckerManager& mgr) {
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
    registry.addChecker<PointerComparisonChecker>("anzu.PointerComparisonChecker", "Prohibit logical comparisons between pointers", "");
}

#endif