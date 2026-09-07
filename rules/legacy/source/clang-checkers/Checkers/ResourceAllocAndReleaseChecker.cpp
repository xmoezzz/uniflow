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
#include <unordered_map>

using namespace clang;
using namespace ento;

namespace {
	std::unordered_map<std::string, int> OpenResources =
	{
		{"socket", -1},
		{"WSASocketA", -1},
		{"WSASocketW", -1},
	};

	std::unordered_map<std::string, int> CloseResources =
	{
		{"closesocket", 0},
		{"shutdown", 0},
	};

	std::unordered_map<std::string, int> UseResources =
	{
		{"listen", 0},
		{"accept", 0},
		{"connect", 0},
		{"bind", 0},
		{"ioctlsocket", 0},
		{"getpeername", 0},
		{"getsockname", 0},
		{"getsockopt", 0},
		{"setsockopt", 0},
		{"send", 0},
		{"recv", 0},
		{"sendto", 0},
		{"recvfrom", 0},
		{"WSAAsyncSelect", 0},
		{"WSAAccept", 0},
		{"WSAConnect", 0},
		{"WSAConnectByNameA", 0},
		{"WSAConnectByNameW", 0},
		{"WSAConnectByList", 0},
		{"WSADuplicateSocketA", 0},
		{"WSADuplicateSocketW", 0},
		{"WSAEnumNetworkEvents", 0},
		{"WSAEventSelect", 0},
		{"WSAGetOverlappedResult", 0},
		{"WSAGetQOSByName", 0},
		{"WSARecv", 0},
		{"WSARecvFrom", 0},
		{"WSASend", 0},
		{"WSASendTo", 0},
		{"WSASendMsg", 0},
	};

	enum class RESOURCE_STATUE {
		RESOURCE_STATUE_NONE,
		RESOURCE_STATUE_OPENED,
		RESOURCE_STATUE_RELEASED,
	};

	class ResourceAllocAndReleaseChecker : public Checker<check::PreCall, 
															check::PostCall,
															check::DeadSymbols> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;
		void checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const;

	private:
		void checkOpenResource(const Expr* E, const SVal& V, CheckerContext& C) const;
		void checkCloseResource(const Expr* E, const SVal& V, CheckerContext& C) const;
		void checkUseResource(const Expr* E, const SVal& V, CheckerContext& C) const;

	private:
		void reportBug(CheckerContext& C, const std::string& Msg) const;
	};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(ResourceStatus, SymbolRef, RESOURCE_STATUE)

void ResourceAllocAndReleaseChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (auto D = Call.getDecl()) {
		if (auto FD = dyn_cast<FunctionDecl>(D)) {
			auto FName = FD->getNameAsString();

			auto It = CloseResources.find(FName);
			if (It != CloseResources.end()) {
				if (It->second < Call.getNumArgs()) {
					if (auto E = Call.getArgExpr(It->second)) {
						checkCloseResource(E, Call.getArgSVal(It->second), C);
					}
				}
				return;
			}

			auto It2 = UseResources.find(FName);
			if (It2 != UseResources.end()) {
				if (It2->second < Call.getNumArgs()) {
					if (auto E = Call.getArgExpr(It2->second)) {
						checkUseResource(E, Call.getArgSVal(It2->second), C);
					}
				}
				return;
			}
		}
	}
}

void ResourceAllocAndReleaseChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
	if (auto D = Call.getDecl()) {
		if (auto FD = dyn_cast<FunctionDecl>(D)) {
			auto FName = FD->getNameAsString();

			auto It = OpenResources.find(FName);
			if (It != OpenResources.end()) {
				if (It->second == -1) {
					checkOpenResource(Call.getOriginExpr(), Call.getReturnValue(), C);
				}
				else if (It->second < Call.getNumArgs()) {
					if (auto E = Call.getArgExpr(It->second)) {
						checkOpenResource(E, Call.getArgSVal(It->second), C);
					}
				}
				return;
			}
		}
	}
}

void ResourceAllocAndReleaseChecker::checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const {
	auto State = C.getState();
	auto Pointers = State->get<ResourceStatus>();
	bool AddState = false;
	for (auto& Pointer : Pointers) {
		auto Sym = Pointer.first;
		bool IsSymDead = SymReaper.isDead(Sym);
		if (IsSymDead) {
			State = State->remove<ResourceStatus>(Sym);
			AddState = true;
		}
	}

	if (AddState) {
		C.addTransition(State);
	}
}

void ResourceAllocAndReleaseChecker::checkOpenResource(const Expr* E, const SVal& V, CheckerContext& C) const {
	if (auto Sym = V.getAsSymbol()) {
		auto State = C.getState();
		State = State->set<ResourceStatus>(Sym, RESOURCE_STATUE::RESOURCE_STATUE_OPENED);
		C.addTransition(State);
	}
}

void ResourceAllocAndReleaseChecker::checkCloseResource(const Expr* E, const SVal& V, CheckerContext& C) const {
	if (auto Sym = V.getAsSymbol()) {
		if (auto Status = C.getState()->get<ResourceStatus>(Sym)) {
			if (*Status == RESOURCE_STATUE::RESOURCE_STATUE_RELEASED) {
				// double release
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string fmt = ls->parseMsgs(anzulocalization::ResourceAllocAndReleaseChecker, lang, 0);
				std::string expr = ToString(E);
				std::string Msg = std::vformat(fmt, std::make_format_args(expr));
				reportBug(C, Msg);
				return;
			}
		}

		ProgramStateRef State = C.getState();
		State = State->set<ResourceStatus>(Sym, RESOURCE_STATUE::RESOURCE_STATUE_RELEASED);
		C.addTransition(State);
	}
}

void ResourceAllocAndReleaseChecker::checkUseResource(const Expr* E, const SVal& V, CheckerContext& C) const {
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	if (V.isUndef()) {
		if (C.getASTContext().HasSyntaxErrors()) {
			return;
		}
		// uninit
		std::string fmt = ls->parseMsgs(anzulocalization::ResourceAllocAndReleaseChecker, lang, 1);
		std::string expr = ToString(E);
		std::string Msg = std::vformat(fmt, std::make_format_args(expr));
		reportBug(C, Msg);
		return;
	}
	if (auto Sym = V.getAsSymbol()) {
		if (auto Status = C.getState()->get<ResourceStatus>(Sym)) {
			if (*Status == RESOURCE_STATUE::RESOURCE_STATUE_RELEASED) {
				// already close
				std::string fmt = ls->parseMsgs(anzulocalization::ResourceAllocAndReleaseChecker, lang, 0);
				std::string expr = ToString(E);
				std::string Msg = std::vformat(fmt, std::make_format_args(expr));
				reportBug(C, Msg);
			}
		}
	}
}

void ResourceAllocAndReleaseChecker::reportBug(CheckerContext& C, const std::string& Msg) const {
	if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
		if (!BT)
			BT.reset(new BuiltinBug(this, "ResourceAllocAndReleaseChecker"));

		auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "ResourceAllocAndReleaseChecker"), Msg, N);
		C.emitReport(std::move(R));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerResourceAllocAndReleaseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ResourceAllocAndReleaseChecker>();
}

bool ento::shouldRegisterResourceAllocAndReleaseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ResourceAllocAndReleaseChecker>("anzu1.ResourceAllocAndReleaseChecker", "", "");
}

#endif
