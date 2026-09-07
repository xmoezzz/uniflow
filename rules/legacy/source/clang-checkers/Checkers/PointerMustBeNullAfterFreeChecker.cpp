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
		POINTER_STATUE_NONE,
		POINTER_STATUE_USED,
		POINTER_STATUE_RELEASED,
	};

	class PointerMustBeNullAfterFreeChecker : public Checker<check::PreCall,
		check::PreStmt<UnaryOperator>,
		check::PreStmt<MemberExpr>,
		check::PreStmt<ArraySubscriptExpr>,
		check::DeadSymbols> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPreStmt(const UnaryOperator* UO, CheckerContext& C) const;
		void checkPreStmt(const MemberExpr* ME, CheckerContext& C) const;
		void checkPreStmt(const ArraySubscriptExpr* ASE, CheckerContext& C) const;
		void checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const;

	private:
		void checkFree(const CallEvent& Call, CheckerContext& C) const;
		void checkDoubleFree(const Expr* E, const SVal& V, CheckerContext& C) const;
		void checkDanglingPointer(const Expr* E, CheckerContext& C) const;

	private:
		void reportBug(CheckerContext& C, const std::string& Msg) const;
	};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(PointerStatus, SymbolRef, POINTER_STATUE)

void PointerMustBeNullAfterFreeChecker::checkFree(const CallEvent& Call, CheckerContext& C) const {
	checkDoubleFree(Call.getArgExpr(0), Call.getArgSVal(0), C);
	if (auto Sym = Call.getArgSVal(0).getAsSymbol()) {
		ProgramStateRef State = C.getState();
		State = State->set<PointerStatus>(Sym, POINTER_STATUE_RELEASED);
		C.addTransition(State);
	}
}

void PointerMustBeNullAfterFreeChecker::checkDoubleFree(const Expr* E, const SVal& V, CheckerContext& C) const {
	if (auto Sym = V.getAsSymbol()) {
		if (auto Status = C.getState()->get<PointerStatus>(Sym)) {
			if (*Status == POINTER_STATUE_RELEASED) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string fmt = ls->parseMsgs(anzulocalization::PointerMustBeNullAfterFreeChecker, lang);
				std::string expr = ToString(E);
				std::string Msg = std::vformat(fmt, std::make_format_args(expr));
				reportBug(C, Msg);
			}
		}
	}
}

void PointerMustBeNullAfterFreeChecker::checkDanglingPointer(const Expr* E, CheckerContext& C) const {
	if (E) {
		if (auto Sym = C.getSVal(E).getAsSymbol()) {
			if (auto Status = C.getState()->get<PointerStatus>(Sym)) {
				if (*Status == POINTER_STATUE_RELEASED) {
					auto ls = anzulocalization::LocaleSetting::getInstance();
					uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
					std::string fmt = ls->parseMsgs(anzulocalization::PointerMustBeNullAfterFreeChecker, lang);
					std::string expr = ToString(E);
					std::string Msg = std::vformat(fmt, std::make_format_args(expr));
					reportBug(C, Msg);
				}
			}
		}
	}
}

void PointerMustBeNullAfterFreeChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (auto D = Call.getDecl()) {
		if (auto FD = dyn_cast<FunctionDecl>(D)) {
			if (Call.getNumArgs() < 1)
				return;

			// free
			auto FName = FD->getNameAsString();
			if (FName == "free" || FName == "operator delete" || FName == "operator delete[]") {
				checkFree(Call, C);
			}
		}
	}
}

void PointerMustBeNullAfterFreeChecker::checkPreStmt(const UnaryOperator* UO, CheckerContext& C) const {
	if (UO->getOpcode() == UnaryOperator::Opcode::UO_Deref) {
		checkDanglingPointer(UO->getSubExpr(), C);
	}
}

void PointerMustBeNullAfterFreeChecker::checkPreStmt(const MemberExpr* ME, CheckerContext& C) const {
	checkDanglingPointer(ME->getBase(), C);
}

void PointerMustBeNullAfterFreeChecker::checkPreStmt(const ArraySubscriptExpr* ASE, CheckerContext& C) const {
	checkDanglingPointer(ASE->getBase(), C);
}

void PointerMustBeNullAfterFreeChecker::checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const {
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

void PointerMustBeNullAfterFreeChecker::reportBug(CheckerContext& C, const std::string& Msg) const {
	if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
		if (!BT)
			BT.reset(new BuiltinBug(this, "PointerMustBeNullAfterFreeChecker"));

		auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "PointerMustBeNullAfterFreeChecker"), Msg, N);
		C.emitReport(std::move(R));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPointerMustBeNullAfterFreeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PointerMustBeNullAfterFreeChecker>();
}

bool ento::shouldRegisterPointerMustBeNullAfterFreeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PointerMustBeNullAfterFreeChecker>("anzu.PointerMustBeNullAfterFreeChecker", "After a pointer variable is released, it should be set to NULL.", "");
}

#endif
