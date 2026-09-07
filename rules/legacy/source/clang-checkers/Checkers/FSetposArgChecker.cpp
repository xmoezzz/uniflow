#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <vector>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	enum FILE_POS {
		FILE_POS_FROM_NONE,
		FILE_POS_FROM_GET,
	};

	class FSetposArgChecker : public Checker<check::PreCall,
		check::PostCall,
		check::DeadSymbols> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;
		void checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const;

	private:
		void reportBug(CheckerContext& C, const std::string& Msg) const;
	};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(FilePosState, SymbolRef, FILE_POS)

void FSetposArgChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (!Call.isGlobalCFunction("fsetpos")) {
		return;
	}

	if (2 > Call.getNumArgs()) {
		return;
	}

	auto PosVal = Call.getArgSVal(1);
	if (auto R = PosVal.getAsRegion()) {
		PosVal = C.getState()->getSVal(R);
		if (auto Sym = PosVal.getAsSymbol()) {
			auto State = C.getState();
			if (auto S = State->get<FilePosState>(Sym)) {
				if (*S == FILE_POS_FROM_GET) {
					return;
				}
			}
		}
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::FSetposArgChecker, lang);
		reportBug(C, Msg);
	}
}

void FSetposArgChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
	if (!Call.isGlobalCFunction("fgetpos")) {
		return;
	}

	if (2 > Call.getNumArgs()) {
		return;
	}

	auto PosVal = Call.getArgSVal(1);
	if (auto R = PosVal.getAsRegion()) {
		PosVal = C.getState()->getSVal(R);
		if (auto Sym = PosVal.getAsSymbol()) {
			auto State = C.getState();
			State = State->set<FilePosState>(Sym, FILE_POS_FROM_GET);
			C.addTransition(State);
		}
	}
}

void FSetposArgChecker::checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const {
	auto State = C.getState();
	auto States = State->get<FilePosState>();
	bool AddState = false;
	for (auto& S : States) {
		auto Sym = S.first;
		if (SymReaper.isDead(Sym)) {
			State = State->remove<FilePosState>(Sym);
			AddState = true;
		}
	}

	if (AddState) {
		C.addTransition(State);
	}
}

void FSetposArgChecker::reportBug(CheckerContext& C, const std::string& Msg) const {
	if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
		if (!BT)
			BT.reset(new BuiltinBug(this, "FSetposArgChecker"));

		auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "FSetposArgChecker"), Msg, N);
		C.emitReport(std::move(R));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFSetposArgChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FSetposArgChecker>();
}

bool ento::shouldRegisterFSetposArgChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FSetposArgChecker>("anzu.FSetposArgChecker", "", "");
}

#endif
