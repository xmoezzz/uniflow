#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class CopyWithoutResizeChecker : public Checker<check::PreCall, check::PostStmt<DeclStmt>, check::DeadSymbols> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& msg, CheckerContext& C) const;
		void checkPostStmt(const DeclStmt* DS, CheckerContext& Ctx) const;
		void checkDeadSymbols(SymbolReaper& SR, CheckerContext& Ctx) const;

		SymbolRef getSym(ProgramStateRef State, const SVal& V) const;
		bool setResize(const CallEvent& Call, CheckerContext& C) const;
		void checkCopy(const CallEvent& Call, CheckerContext& C) const;
		const CXXMemberCallExpr* getMCE(const Expr* E) const;
		void reportBug(std::string& Msg, CheckerContext& C) const;
	};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(ResizeState, const VarDecl*, bool)

void CopyWithoutResizeChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (setResize(Call, C))
		return;

	checkCopy(Call, C);
}

void CopyWithoutResizeChecker::checkPostStmt(const DeclStmt* DS, CheckerContext& Ctx) const {
	ProgramStateRef State = Ctx.getState();

	bool IsUpdate = false;
	for (const Decl* D : DS->decls()) {
		// Check if the Decl is a VarDecl
		if (const VarDecl* VD = llvm::dyn_cast_or_null<VarDecl>(D)) {
			if (auto RD = VD->getType()->getAsCXXRecordDecl()) {
				auto TName = RD->getQualifiedNameAsString();
				// Check if the type is an iterator; This is a simplistic approach. In a real-world scenario, 
				// you might need a more comprehensive type checking mechanism.
				if (TName.find("std::vector") == 0) {
					bool Value = false;
					if (const Expr* Init = VD->getInit()) {
						if (auto EWC = dyn_cast<ExprWithCleanups>(Init->IgnoreParenCasts())) {
							if (auto SE = EWC->getSubExpr()) {
								Init = SE;
							}
						}

						if (auto CtorE = dyn_cast<CXXConstructExpr>(Init->IgnoreParenCasts())) {
							if (CtorE->getNumArgs() > 0) {
								Value = true;
							}
						}
					}

					State = State->set<ResizeState>(VD, Value);
					IsUpdate = true;
				}
			}
		}
	}

	if (IsUpdate && State)
		Ctx.addTransition(State);
}

void CopyWithoutResizeChecker::checkDeadSymbols(SymbolReaper& SR, CheckerContext& Ctx) const {
	ProgramStateRef State = Ctx.getState();
	ResizeStateTy TrackedIters = State->get<ResizeState>();
	bool IsUpdate = false;
	for (auto Iter : TrackedIters) {
		if (Iter.first) {
			auto LV = State->getLValue(Iter.first, Ctx.getLocationContext());
			auto Val = State->getSVal(LV);
			auto Sym = getSym(State, Val);
			if (!Sym) {
				State = State->remove<ResizeState>(Iter.first);
				IsUpdate = true;
			}
			else if (SR.isDead(Sym)) {
				State = State->remove<ResizeState>(Iter.first);
				IsUpdate = true;
			}
		}
		else{
			State = State->remove<ResizeState>(Iter.first);
			IsUpdate = true;
		}
	}
	if (IsUpdate && State)
		Ctx.addTransition(State);
}

SymbolRef CopyWithoutResizeChecker::getSym(ProgramStateRef State, const SVal& V) const {
	auto Sym = V.getAsSymbol();
	if (!Sym) {
		if (auto LCV = V.getAs<nonloc::LazyCompoundVal>()) {
			if (std::optional<SVal> binding =
				State->getStateManager().getStoreManager().getDefaultBinding(
					*LCV)) {
				Sym = binding->getAsSymbol();
			}
		}
	}

	return Sym;
}

bool CopyWithoutResizeChecker::setResize(const CallEvent& Call, CheckerContext& C) const {
	auto InsCall = dyn_cast<CXXInstanceCall>(&Call);
	if (!InsCall)
		return false;

	auto FD = InsCall->getDecl();
	if (!FD)
		return false;

	const auto* MD = dyn_cast_or_null<CXXMethodDecl>(FD);
	if (!MD)
		return false;

	auto Name = MD->getNameAsString();
	if (Name != "resize")
		return false;

	Name = MD->getQualifiedNameAsString();
	if (Name.find("std::vector") != 0)
		return false;

	auto E = InsCall->getCXXThisExpr();
	if (!E)
		return true;

	auto DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenCasts());
	if (!DRE)
		return true;

	auto ValueD = DRE->getDecl();
	if (!ValueD)
		return true;

	auto VD = dyn_cast<VarDecl>(ValueD);
	if (!VD)
		return true;

	auto State = C.getState();
	if (auto Pointer = State->get<ResizeState>(VD)) {
		if (State = State->set<ResizeState>(VD, true)) {
			C.addTransition(State);
		}
	}

	return true;
}

void CopyWithoutResizeChecker::checkCopy(const CallEvent& Call, CheckerContext& C) const {
	auto D = Call.getDecl();
	if (!D)
		return;

	auto FD = dyn_cast<FunctionDecl>(D);
	if (!FD)
		return;

	if (Call.getNumArgs() != 3)
		return;

	auto Name = FD->getQualifiedNameAsString();
	if (Name != "std::copy")
		return;

	auto Expr = Call.getArgExpr(2);
	if (!Expr)
		return;

	auto MCE = getMCE(Expr);
	if (!MCE)
		return;

	auto ThisExpr = MCE->getImplicitObjectArgument();
	if (!ThisExpr)
		return;

	auto DRE = dyn_cast<DeclRefExpr>(ThisExpr->IgnoreParenCasts());
	if (!DRE)
		return;

	auto ValueD = DRE->getDecl();
	if (!ValueD)
		return;

	auto VD = dyn_cast<VarDecl>(ValueD);
	if (!VD)
		return;

	auto State = C.getState();
	if (auto Pointer = State->get<ResizeState>(VD)) {
		if (!*Pointer) {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::CopyWithoutResizeChecker, lang);
			reportBug(Msg, C);
			return;
		}
	}
}

const CXXMemberCallExpr* CopyWithoutResizeChecker::getMCE(const Expr* E) const {
	if (!E)
		return nullptr;

	auto BTE = dyn_cast<CXXBindTemporaryExpr>(E->IgnoreParenCasts());
	if (!BTE)
		return dyn_cast<CXXMemberCallExpr>(E->IgnoreParenCasts());

	E = BTE->getSubExpr();
	if (!E)
		return nullptr;

	auto CtorE = dyn_cast<CXXConstructExpr>(E->IgnoreParenCasts());
	if (!CtorE)
		return dyn_cast<CXXMemberCallExpr>(E->IgnoreParenCasts());

	if (0 == CtorE->getNumArgs())
		return nullptr;

	E = CtorE->getArg(0);
	if (!E)
		return nullptr;

	BTE = dyn_cast<CXXBindTemporaryExpr>(E->IgnoreParenCasts());
	if (!BTE)
		return dyn_cast<CXXMemberCallExpr>(E->IgnoreParenCasts());

	E = BTE->getSubExpr();
	if (!E)
		return nullptr;

	return dyn_cast<CXXMemberCallExpr>(E);
}

void CopyWithoutResizeChecker::reportBug(std::string& Msg, CheckerContext& C) const {
	if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
		if (!BT)
			BT.reset(new BuiltinBug(this, "CopyWithoutResizeChecker"));

		auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "CopyWithoutResizeChecker"), Msg, N);
		C.emitReport(std::move(R));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCopyWithoutResizeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CopyWithoutResizeChecker>();
	}

bool ento::shouldRegisterCopyWithoutResizeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CopyWithoutResizeChecker>("anzu.CopyWithoutResizeChecker", "", "");
}

#endif