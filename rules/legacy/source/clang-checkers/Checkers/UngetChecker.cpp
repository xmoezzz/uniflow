#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/MemRegion.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

class UngetChecker : public Checker<check::PreCall, check::DeadSymbols> {
	mutable std::unique_ptr<BuiltinBug> BT;

public:
	void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
	void checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const;
	void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
};


REGISTER_MAP_WITH_PROGRAMSTATE(StreamTrack, SymbolRef, bool)

void UngetChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(Call.getDecl());
	if (!FD)
		return;

	if (Call.getNumArgs() != 2)
		return;

	auto Name = FD->getQualifiedNameAsString();
	if (Name != "ungetc" && Name != "ungetwc")
		return;

	const Expr* StreamExpr = Call.getArgExpr(1);
	if (!StreamExpr)
		return;

	SVal StreamVal = C.getSVal(StreamExpr);
	auto Sym = StreamVal.getAsSymbol();
	if (!Sym)
		return;

	auto State = C.getState();
	if (auto Value = State->get<StreamTrack>(Sym)) {
		if (*Value) {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}

			reportBug(FD, StreamExpr->getBeginLoc(), C.getBugReporter());

			if (State = State->set<StreamTrack>(Sym, false)) {
				C.addTransition(State);
			}
		}
	}
	else {
		if (State = State->set<StreamTrack>(Sym, true)) {
			C.addTransition(State);
		}
	}
}

void UngetChecker::checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const {
	auto State = C.getState();
	auto SS = State->get<StreamTrack>();
	bool AddState = false;
	std::vector<SymbolRef> LeakSyms;
	for (auto& S : SS) {
		auto Sym = S.first;
		if (SymReaper.isDead(Sym)) {
			State = State->remove<StreamTrack>(Sym);
			AddState = true;
		}
	}

	if (AddState && State) {
		C.addTransition(State);
	}
}

void UngetChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "UngetChecker"));

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::UngetChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "UngetChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUngetChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UngetChecker>();
}

bool ento::shouldRegisterUngetChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UngetChecker>("anzu.UngetChecker", "Check for multiple ungetc/ungetwc on the same file stream", "");
}

#endif