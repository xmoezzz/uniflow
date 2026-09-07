#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

class AlignedAllocReallocChecker : public Checker<check::PostCall, check::PreCall> {
    mutable std::unique_ptr<BuiltinBug> BT;

public:
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

private:
    bool CheckReallocBug(CheckerContext& C, const MemRegion* MR) const;
};

// Program state trait for tracking allocations from aligned_alloc
REGISTER_TRAIT_WITH_PROGRAMSTATE(AllocatedMemory,  llvm::ImmutableSet<const MemRegion *>);

void AlignedAllocReallocChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
    auto &F = C.getState()->getStateManager().get_context<AllocatedMemory>();
    if (Call.getCalleeIdentifier()) {
        auto FunctionName = Call.getCalleeIdentifier()->getName();
        if (FunctionName == "aligned_alloc" ||
            FunctionName == "_aligned_malloc") {
            if (const MemRegion* MR = Call.getReturnValue().getAsRegion()) {
                llvm::ImmutableSet<const MemRegion*> S = C.getState()->get<AllocatedMemory>();
                auto&& Result = F.add(S, MR);
                ProgramStateRef State = C.getState()->set<AllocatedMemory>(Result);
                C.addTransition(State);
            }
        }
        else if (FunctionName == "free") {
            const MemRegion* MR = Call.getArgSVal(0).getAsRegion();
            llvm::ImmutableSet<const MemRegion*> S = C.getState()->get<AllocatedMemory>();
            auto&& Result = F.remove(S, MR);
            ProgramStateRef State = C.getState()->set<AllocatedMemory>(Result);
            C.addTransition(State);
        }
    }
}

void AlignedAllocReallocChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (Call.getCalleeIdentifier() && Call.getCalleeIdentifier()->getName() == "realloc") {
        const MemRegion *MR = Call.getArgSVal(0).getAsRegion();
        if (MR) {
            if (!CheckReallocBug(C, MR)) {
                if (auto SR = dyn_cast<SubRegion>(MR)) {
                    CheckReallocBug(C, SR->getSuperRegion());
                }
            }
        }        
    }
}

bool AlignedAllocReallocChecker::CheckReallocBug(CheckerContext& C, const MemRegion* MR) const {
    llvm::ImmutableSet<const MemRegion*> S = C.getState()->get<AllocatedMemory>();
    if (MR && C.getState()->contains<AllocatedMemory>(MR)) {
        if (!BT) {
            BT.reset(new BuiltinBug(this, "AlignedAllocReallocChecker"));
        }
        if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
            auto ls = anzulocalization::LocaleSetting::getInstance();
            uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
            std::string msg = ls->parseMsgs(anzulocalization::AlignedAllocReallocChecker, lang);
            auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "AlignedAllocReallocChecker"), msg, N);
            C.emitReport(std::move(R));
		}
        return true;
    }

    return false;
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAlignedAllocReallocChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<AlignedAllocReallocChecker>();
}

bool ento::shouldRegisterAlignedAllocReallocChecker(const CheckerManager& mgr) {
    return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::C);
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
    registry.addChecker<AlignedAllocReallocChecker>("anzu.AlignedAllocReallocChecker", "", "");
}

#endif