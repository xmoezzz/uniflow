#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	enum POINTER_STATUE {
		POINTER_STATUE_ALLOC,
	};

	class DynamicAllocPointerUseChecker : public Checker<check::PostCall,
															check::PreStmt<UnaryOperator>, 
															check::PreStmt<MemberExpr>, 
															check::PreStmt<ArraySubscriptExpr>,
															check::DeadSymbols> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPreStmt(const UnaryOperator* UO, CheckerContext& C) const;
		void checkPreStmt(const MemberExpr* ME, CheckerContext& C) const;
		void checkPreStmt(const ArraySubscriptExpr* ASE, CheckerContext& C) const;
		void checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const;

	private:
		void checkMalloc(const CallEvent& Call, CheckerContext& C) const;
		void checkNullPointer(const Expr* E, CheckerContext& C) const;

	private:
		void reportBug(CheckerContext& C, const std::string& Msg) const;
	};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(PointerStatus, SymbolRef, POINTER_STATUE)

void DynamicAllocPointerUseChecker::checkMalloc(const CallEvent& Call, CheckerContext& C) const {

	if (auto Sym = Call.getReturnValue().getAsSymbol()) {
		ProgramStateRef State = C.getState();
		State = State->set<PointerStatus>(Sym, POINTER_STATUE_ALLOC);
		C.addTransition(State);
	}
}

void DynamicAllocPointerUseChecker::checkNullPointer(const Expr* E, CheckerContext& C) const {
	if (E) {
		auto V = C.getSVal(E);
		if (auto DS = dyn_cast<DefinedSVal>(V)) {
			if (auto Sym = V.getAsSymbol()) {
				auto State = C.getState();
				if (auto Pointer = State->get<PointerStatus>(Sym)) {
					if (*Pointer == POINTER_STATUE_ALLOC) {
						auto& CM = C.getConstraintManager();
						ProgramStateRef stateNotZero, stateZero;
						std::tie(stateNotZero, stateZero) = CM.assumeDual(State, *DS);
						if (stateZero) {
							auto ls = anzulocalization::LocaleSetting::getInstance();
							uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
							std::string Msg = ls->parseMsgs(anzulocalization::DynamicAllocPointerUseChecker, lang);
							reportBug(C, Msg);
						}
					}
				}
			}
		}
	}
}

void DynamicAllocPointerUseChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
	if (auto D = Call.getDecl()) {
		if (auto FD = dyn_cast<FunctionDecl>(D)) {
			if (!Call.getOriginExpr()) 
				return;

			// alloc
			auto FName = FD->getNameAsString();
			if (FName == "malloc" || FName == "calloc" || FName == "operator new" || FName == "operator new[]") {
				checkMalloc(Call, C);
			}
		}
	}
}

void DynamicAllocPointerUseChecker::checkPreStmt(const UnaryOperator* UO, CheckerContext& C) const {
	if (UO->getOpcode() == UnaryOperator::Opcode::UO_Deref) {
		checkNullPointer(UO->getSubExpr(), C);
	}
}

void DynamicAllocPointerUseChecker::checkPreStmt(const MemberExpr* ME, CheckerContext& C) const {
	checkNullPointer(ME->getBase(), C);
}

void DynamicAllocPointerUseChecker::checkPreStmt(const ArraySubscriptExpr* ASE, CheckerContext& C) const {
	checkNullPointer(ASE->getBase(), C);
}

void DynamicAllocPointerUseChecker::checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const {
	auto State = C.getState();
	auto Pointers = State->get<PointerStatus>();
	bool AddState = false;
	for (auto& Pointer : Pointers) {
		auto Sym = Pointer.first;
		bool IsSymDead = SymReaper.isDead(Sym);
		if (IsSymDead) {
			State = State->remove<PointerStatus>(Sym);
			AddState = true;
		}
	}

	if (AddState) {
		C.addTransition(State);
	}
}


void DynamicAllocPointerUseChecker::reportBug(CheckerContext& C, const std::string& Msg) const {
	if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
		if (!BT)
			BT.reset(new BuiltinBug(this, "DynamicAllocPointerUseChecker"));

		auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "DynamicAllocPointerUseChecker"), Msg, N);
		C.emitReport(std::move(R));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDynamicAllocPointerUseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<DynamicAllocPointerUseChecker>();
}

bool ento::shouldRegisterDynamicAllocPointerUseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<DynamicAllocPointerUseChecker>("anzu.DynamicAllocPointerUseChecker", "A dynamically allocated pointer variable must be checked for NULL before its first use.", "");
}

#endif
