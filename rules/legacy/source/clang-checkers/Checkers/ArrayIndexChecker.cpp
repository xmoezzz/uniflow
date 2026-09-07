#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
class ArrayIndexChecker2 : public Checker<check::PreStmt<ArraySubscriptExpr>> {
    mutable std::unique_ptr<BuiltinBug> BT;

public:
  void checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const;
};
} // end anonymous namespace

void ArrayIndexChecker2::checkPreStmt(const ArraySubscriptExpr *ASE, CheckerContext &C) const {
    if (C.getASTContext().HasSyntaxErrors()) {
        return;
    }

  // 获取下标的符号值
    SVal indexVal = C.getSVal(ASE->getIdx());
    if (!indexVal.getAs<NonLoc>())
        return;

    // 检查下标是否可能小于零
    auto rhs = C.getSValBuilder().makeZeroVal(C.getSValBuilder().getConditionType()).castAs<NonLoc>();
    SVal compareVal = C.getSValBuilder().evalBinOpNN(C.getState(), BO_LT, indexVal.castAs<NonLoc>(), rhs, C.getSValBuilder().getConditionType());
    if (!dyn_cast<DefinedSVal>(compareVal)) {
        return;
    }

    // 获取新的程序状态
    ProgramStateRef stateTrue, stateFalse;
    std::tie(stateTrue, stateFalse) = C.getState()->assume(compareVal.castAs<DefinedSVal>());

    // 如果存在下标小于零的状态，则报告错误
    if (stateTrue) {
        if (ExplodedNode *N = C.generateNonFatalErrorNode(stateTrue)) {
            if (!BT) 
                BT.reset(new BuiltinBug(this, "ArrayIndexChecker2"));
            auto ls = anzulocalization::LocaleSetting::getInstance();
		    uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		    std::string msg = ls->parseMsgs(anzulocalization::ArrayIndexChecker2, lang);        
            auto report = std::make_unique<PathSensitiveBugReport>(*BT, 
                createRuleExtData(1, "ArrayIndexChecker2"), msg, N);
            C.emitReport(std::move(report));
        }
    }
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerArrayIndexChecker2(CheckerManager& Mgr) {
    Mgr.registerChecker<ArrayIndexChecker2>();
}

bool ento::shouldRegisterArrayIndexChecker2(const CheckerManager& mgr) {
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
    registry.addChecker<ArrayIndexChecker2>("anzu.ArrayIndexChecker2", "Checks for array index less than zero", "");
}

#endif