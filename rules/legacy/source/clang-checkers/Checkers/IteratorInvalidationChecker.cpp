#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

class IteratorInvalidationChecker : public Checker<check::PreCall, check::PostStmt<DeclStmt>, check::DeadSymbols> {
private:
	mutable std::unique_ptr<BuiltinBug> BT;

	bool isPotentiallyInvalidatingMethod(const CXXMethodDecl* MD) const {
		// You might want to refine this list.
		const char* InvalidatingMethods[] = {
			"std::deque::insert",
			"std::vector::insert",
			"std::list::pop_front",
			"std::vector::erase"
		};

		if (!MD)
			return false;

		for (const char* Name : InvalidatingMethods) {
			if (MD->getQualifiedNameAsString() == Name)
				return true;
		}
		return false;
	}

public:
	void checkPreCall(const CallEvent& msg, CheckerContext& C) const;
	void checkPostStmt(const DeclStmt* DS, CheckerContext& Ctx) const;
	void checkDeadSymbols(SymbolReaper& SR, CheckerContext& Ctx) const;
	void reportBug(const char* Msg, CheckerContext& C) const;
};

REGISTER_MAP_WITH_PROGRAMSTATE(IteratorState, SymbolRef, bool)

void IteratorInvalidationChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	auto Str = ToString(Call);
	auto InsCall = dyn_cast<CXXInstanceCall>(&Call);
	if (!InsCall)
		return;

	auto FD = InsCall->getDecl();
	if (!FD)
		return;

	const auto* MD = dyn_cast_or_null<CXXMethodDecl>(FD);
	if (!MD)
		return;

	SymbolRef Sym = InsCall->getCXXThisVal().getAsSymbol();
	if (!Sym)
		return;

	ProgramStateRef State = C.getState();
	if (auto Pointer = State->get<IteratorState>(Sym)) {
		if (*Pointer) {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::IteratorInvalidationChecker, lang);

			reportBug(Msg, C);
			return;
		}

		if (!isPotentiallyInvalidatingMethod(MD))
			return;

		if (State = State->set<IteratorState>(Sym, true))
			C.addTransition(State);
	}
}

void IteratorInvalidationChecker::checkPostStmt(const DeclStmt* DS, CheckerContext& Ctx) const {
	ProgramStateRef State = Ctx.getState();
	auto Str = ToString(DS);

	bool IsUpdate = false;
	for (const Decl* D : DS->decls()) {
		// Check if the Decl is a VarDecl
		if (const VarDecl* VD = llvm::dyn_cast_or_null<VarDecl>(D)) {
			const QualType QT = VD->getType();
			auto TName = QT.getAsString();
			// Check if the type is an iterator; This is a simplistic approach. In a real-world scenario, 
			// you might need a more comprehensive type checking mechanism.
			if (TName.find("iterator") != std::string::npos) {
				auto ValLV = State->getLValue(VD, Ctx.getLocationContext());
				auto Val = State->getSVal(ValLV);
				auto Sym = Val.getAsSymbol();
				if (!Sym) {
					if (auto LCV = Val.getAs<nonloc::LazyCompoundVal>()) {
						if (std::optional<SVal> binding =
							State->getStateManager().getStoreManager().getDefaultBinding(
								*LCV)) {
							Sym = binding->getAsSymbol();
						}
					}
				}

				if (Sym) {
					State = State->set<IteratorState>(Sym, false);
					IsUpdate = true;
				}
			}
		}
	}

	if (IsUpdate && State)
		Ctx.addTransition(State);
}

void IteratorInvalidationChecker::checkDeadSymbols(SymbolReaper& SR, CheckerContext& Ctx) const {
	ProgramStateRef State = Ctx.getState();
	IteratorStateTy TrackedIters = State->get<IteratorState>();
	bool IsUpdate = false;
	for (auto Iter : TrackedIters) {
		if (SR.isDead(Iter.first)) {
			State = State->remove<IteratorState>(Iter.first);
			IsUpdate = true;
		}
	}
	if (IsUpdate && State)
		Ctx.addTransition(State);
}

void IteratorInvalidationChecker::reportBug(const char* Msg, CheckerContext& C) const {
	if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
		if (!BT)
			BT.reset(new BuiltinBug(this, "IteratorInvalidationChecker"));

		auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "IteratorInvalidationChecker"), Msg, N);
		C.emitReport(std::move(R));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerIteratorInvalidationChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<IteratorInvalidationChecker>();
}

bool ento::shouldRegisterIteratorInvalidationChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::CPP);
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
	registry.addChecker<IteratorInvalidationChecker>("anzu1.IteratorInvalidationChecker", "Do not pass null pointer to char_traits::length", "");
}

#endif