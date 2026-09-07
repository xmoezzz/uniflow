#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include "../Utils.h"

using namespace llvm;
using namespace clang;
using namespace ento;

REGISTER_MAP_WITH_PROGRAMSTATE(OriginTypeInfo, SymbolRef, const CXXRecordDecl*)

namespace {

	class VirtualDtorChecker : public Checker<check::PostStmt<CXXNewExpr>, check::PreStmt<CXXDeleteExpr>, check::DeadSymbols> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPostStmt(const CXXNewExpr* NE, CheckerContext& C) const;
		void checkPreStmt(const CXXDeleteExpr* DE, CheckerContext& C) const;
		void checkDeadSymbols(SymbolReaper& SR, CheckerContext& C) const;

		void reportBug(std::string& Msg, CheckerContext& C) const;
	};


	void VirtualDtorChecker::checkPostStmt(const CXXNewExpr* NE, CheckerContext& C) const {
		auto State = C.getState();
		auto Val = State->getSVal(NE, C.getLocationContext());
		auto Sym = Val.getAsSymbol();
		if (!Sym)
			return;

		auto RD = NE->getAllocatedType()->getAsCXXRecordDecl();
		if (!RD)
			return;

		auto Dtor = RD->getDestructor();
		if (!Dtor)
			return;

		if (Dtor->isVirtual())
			return;

		if (State = State->set<OriginTypeInfo>(Sym, RD)) {
			C.addTransition(State);
		}
	}

	void VirtualDtorChecker::checkPreStmt(const CXXDeleteExpr* DE, CheckerContext& C) const {
		const Expr* Arg = DE->getArgument();
		if (!Arg)
			return;

		auto PT = dyn_cast<PointerType>(Arg->getType().getTypePtr());
		if (!PT)
			return;

		auto RD = PT->getPointeeType()->getAsCXXRecordDecl();
		if (!RD)
			return;

		auto Val = C.getSVal(Arg);
		auto Sym = Val.getAsSymbol();
		if (!Sym)
			return;

		auto State = C.getState();
		if (auto Info = State->get<OriginTypeInfo>(Sym)) {
			if (*Info != RD) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string fmt = ls->parseMsgs(anzulocalization::VirtualDtorChecker, lang);
				std::string rd = RD->getNameAsString();
				std::string Msg = std::vformat(fmt, std::make_format_args(rd));
				reportBug(Msg, C);
			}
		}
	}

	void VirtualDtorChecker::checkDeadSymbols(SymbolReaper& SR, CheckerContext& C) const {
		auto State = C.getState();
		auto Pointers = State->get<OriginTypeInfo>();
		bool AddState = false;
		for (auto& Pointer : Pointers) {
			auto Sym = Pointer.first;
			bool IsSymDead = SR.isDead(Sym);
			if (IsSymDead) {
				State = State->remove<OriginTypeInfo>(Sym);
				AddState = true;
			}
		}

		if (AddState && State) {
			C.addTransition(State);
		}
	}

	void VirtualDtorChecker::reportBug(std::string& Msg, CheckerContext& C) const {
		if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
			if (!BT)
				BT.reset(new BuiltinBug(this, "CopyWithoutResizeChecker"));

			auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "VirtualDtorChecker"), Msg, N);
			C.emitReport(std::move(R));
		}
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerVirtualDtorChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<VirtualDtorChecker>();
}

bool ento::shouldRegisterVirtualDtorChecker(const CheckerManager& mgr) {
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
	registry.addChecker<VirtualDtorChecker>("anzu.VirtualDtorChecker", "", "");
}

#endif