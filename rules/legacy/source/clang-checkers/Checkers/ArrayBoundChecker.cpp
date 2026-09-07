#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicExtent.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
    class ArrayBoundChecker2 : public Checker<check::PreStmt<ArraySubscriptExpr>> {
        mutable std::unique_ptr<BuiltinBug> BT;

    public:
        void checkPreStmt(const ArraySubscriptExpr* ASE, CheckerContext& C) const;
    };
} // end anonymous namespace

void ArrayBoundChecker2::checkPreStmt(const ArraySubscriptExpr* ASE, CheckerContext& C) const {
    if (C.getASTContext().HasSyntaxErrors()) {
        return;
    }

    if (ASE->getBeginLoc().isMacroID()) {
        return;
    }

    // 获取数组和下标的符号值
    SVal indexVal = C.getSVal(ASE->getIdx());
    SVal arrayVal = C.getSVal(ASE->getBase());

    if (!dyn_cast<NonLoc>(indexVal)) {
        return;
    }

    // 获取数组大小
    Optional<Loc> arrayLoc = arrayVal.getAs<Loc>();
    if (!arrayLoc)
        return;

    const MemRegion* arrayRegion = arrayLoc->getAsRegion();
    if (!arrayRegion) {
        return;
    }

    const ElementRegion* ER = llvm::dyn_cast_or_null<ElementRegion>(arrayRegion);
    if (!ER) {
        return;
    }

    auto SR = ER->getSuperRegion();
    if (!SR) {
        return;
    }

    auto arraySizeVal = getDynamicElementCount(
        C.getState(), SR, C.getSValBuilder(), ER->getValueType());
    if (!dyn_cast<NonLoc>(arraySizeVal)) {
        return;
    }

    // 排除获取数组大小失败
    auto ZeroVal = C.getSValBuilder().makeZeroVal(arraySizeVal.getType(C.getASTContext()));
    auto IsZero = C.getSValBuilder().evalEQ(C.getState(), ZeroVal, arraySizeVal);
    if (!dyn_cast<DefinedSVal>(IsZero)) {
        return;
    }
    if (C.getState()->assume(IsZero.castAs<DefinedSVal>()).first) {
        return;
    }

    // 比较下标和数组大小
    SVal compareVal = C.getSValBuilder().evalBinOpNN(C.getState(), BO_GE, indexVal.castAs<NonLoc>(), arraySizeVal.castAs<NonLoc>(), C.getSValBuilder().getConditionType());
    if (!dyn_cast<DefinedSVal>(compareVal)) {
        return;
    }

    // 获取新的程序状态
    ProgramStateRef stateTrue, stateFalse;
    std::tie(stateTrue, stateFalse) = C.getState()->assume(compareVal.castAs<DefinedSVal>());

    // 如果存在越界状态，则报告错误
    if (stateTrue) {
        if (ExplodedNode* N = C.generateNonFatalErrorNode(stateTrue)) {
            if (!BT)
                BT.reset(new BuiltinBug(this, "ArrayBoundChecker2"));

            auto ls = anzulocalization::LocaleSetting::getInstance();
		    uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		    std::string msg = ls->parseMsgs(anzulocalization::ArrayBoundChecker2, lang);
            auto report = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "ArrayBoundChecker2"), msg, N);
            C.emitReport(std::move(report));
        }
    }

}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerArrayBoundChecker2(CheckerManager& Mgr) {
    Mgr.registerChecker<ArrayBoundChecker2>();
}

bool ento::shouldRegisterArrayBoundChecker2(const CheckerManager& mgr) {
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
    registry.addChecker<ArrayBoundChecker2>("anzu.ArrayBoundChecker2", "Checks for array bound read/write exceeds size", "");
}

#endif