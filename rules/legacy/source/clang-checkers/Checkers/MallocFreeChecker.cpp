#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

REGISTER_MAP_WITH_PROGRAMSTATE(TaintMap, SymbolRef, bool)

namespace {
	class MallocFreeChecker : public Checker<check::PreCall, check::PostCall> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;
	};
} // end anonymous namespace

void MallocFreeChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	ProgramStateRef State = C.getState();
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::MallocFreeChecker, lang);
	// 检查是否调用了 "free"
	if (const IdentifierInfo* II = Call.getCalleeIdentifier()) {
		if (II->isStr("free") && Call.getNumArgs() > 0) {
			// 获取 "free" 调用的参数
			SVal ArgVal = Call.getArgSVal(0);
			auto Sym = ArgVal.getAsSymbol();

			// 检查指针是否被污染（即由malloc或calloc分配）
			if (Sym && !State->contains<TaintMap>(Sym)) {
				ExplodedNode* N = C.generateNonFatalErrorNode();
				if (N) {
					if (!BT)
						BT.reset(new BuiltinBug(this, "MallocFreeChecker"));
					auto report = std::make_unique<PathSensitiveBugReport>(*BT,
						createRuleExtData(1, "MallocFreeChecker"),
						Msg,
						N);
					C.emitReport(std::move(report));
				}
			}
		}
	}
}

void MallocFreeChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
	ProgramStateRef State = C.getState();

	// 检查是否调用了 "malloc" 或 "calloc"
	if (const IdentifierInfo* II = Call.getCalleeIdentifier()) {
		if (II->isStr("malloc") || II->isStr("calloc") || II->isStr("realloc")) {
			// 获取返回值并污染它
			SVal RetVal = Call.getReturnValue();
			if (auto Sym = RetVal.getAsSymbol()) {
				State = State->set<TaintMap>(Sym, true);
				C.addTransition(State);
			}
		}
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMallocFreeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MallocFreeChecker>();
}

bool ento::shouldRegisterMallocFreeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MallocFreeChecker>("anzu.MallocFreeChecker", "Checks if pointer passed to free was allocated by malloc or calloc", "");
}

#endif
