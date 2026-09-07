#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Expr.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

class AssertChecker : public Checker<check::PreStmt<CallExpr>> {
  mutable std::unique_ptr<BuiltinBug> BT;

public:
  void checkPreStmt(const CallExpr *CE, CheckerContext &C) const {
    const auto *FD = C.getCalleeDecl(CE);
    if (!FD || !FD->getIdentifier() || !FD->getIdentifier()->isStr("assert"))
      return;

    if (CE->getNumArgs() != 1)
      return;

    const Expr *AssertExpr = CE->getArg(0);
    if (!AssertExpr)
        return;

    if (!AssertExpr->getType()->isScalarType())
        return;

    SVal Denom = C.getSVal(AssertExpr);
    std::optional<DefinedSVal> DS = Denom.getAs<DefinedSVal>();
    if (!DS)
        return;

    ConstraintManager& CM = C.getConstraintManager();
    ProgramStateRef stateNotZero, stateZero;
    std::tie(stateNotZero, stateZero) = CM.assumeDual(C.getState(), *DS);

    if (stateNotZero && stateZero || !stateNotZero && !stateZero) {
        return;
    }

		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::AssertChecker, lang); 
    std::string state = stateZero ? "false" : "true";
    std::string Msg = std::vformat(fmt, std::make_format_args(state));  
    reportBug(Msg, CE, C);
  }

  void reportBug(const std::string &Msg, const CallExpr *CE, CheckerContext &C) const {
    auto Loc = CE->getBeginLoc();
    if (Loc.isMacroID())
      return;

    if (!BT) {
      BT.reset(new BuiltinBug(this, "AssertChecker"));
    }
    if (auto N = C.generateNonFatalErrorNode()) {
      auto report = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "AssertChecker"), Msg, N);
      C.emitReport(std::move(report));
    }
  }
};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAssertChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<AssertChecker>();
}

bool ento::shouldRegisterAssertChecker(const CheckerManager& mgr) {
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
    registry.addChecker<AssertChecker>("anzu.AssertChecker", "Ensure assertions do not have constant true/false values", "");
}

#endif