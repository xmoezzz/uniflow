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
	enum FILE_STATUE {
		FILE_STATUE_OPENED,
		FILE_STATUE_CLOSED,
	};

	class FilePointerLeakChecker : public Checker<check::PreCall,
		check::PostCall,
		check::DeadSymbols> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;
		void checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const;

	private:
		bool checkLeak(SymbolRef Sym, FILE_STATUE State, CheckerContext& C) const;
		bool checkLeakWithExitMethod(CheckerContext& C) const;

	private:
		void reportBug(CheckerContext& C, ProgramStateRef State, const std::vector<SymbolRef>& Syms, const std::string& Msg, const std::string& RuleID) const;
	};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(FileState, SymbolRef, FILE_STATUE)

void FilePointerLeakChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (!Call.isGlobalCFunction("fclose")) {
		return;
	}

	if (Call.getNumArgs() < 1) {
		return;
	}

	if (auto Sym = Call.getArgSVal(0).getAsSymbol()) {
		auto State = C.getState();
		if (auto S = State->get<FileState>(Sym)) {
			if (*S == FILE_STATUE_CLOSED) {
				// double close
				return;
			}
		}

		State = State->set<FileState>(Sym, FILE_STATUE_CLOSED);
		C.addTransition(State);
	}
}

void FilePointerLeakChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
	if (!Call.isGlobalCFunction("fopen")) {
		return;
	}

	if (auto Sym = Call.getReturnValue().getAsSymbol()) {
		auto State = C.getState();
		State = State->set<FileState>(Sym, FILE_STATUE_OPENED);
		C.addTransition(State);
	}
}

void FilePointerLeakChecker::checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const {
	auto State = C.getState();
	auto FSs = State->get<FileState>();
	bool AddState = false;
	std::vector<SymbolRef> LeakSyms;
	for (auto& FS : FSs) {
		auto Sym = FS.first;
		if (SymReaper.isDead(Sym)) {
			if (checkLeak(Sym, FS.second, C)) {
				LeakSyms.push_back(Sym);
			}
			State = State->remove<FileState>(Sym);
			AddState = true;
		}
	}

	if (!LeakSyms.empty()) {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::FilePointerLeakChecker, lang); 
		if (checkLeakWithExitMethod(C)) {
			reportBug(C, State, LeakSyms, Msg, "FilePointerLeakChecker.1");
		}
		else {
			reportBug(C, State, LeakSyms, Msg, "FilePointerLeakChecker.2");
		}
	}
	else if (AddState) {
		C.addTransition(State);
	}
}

bool FilePointerLeakChecker::checkLeak(SymbolRef Sym, FILE_STATUE State, CheckerContext& C) const {
	if (FILE_STATUE_OPENED == State) {
		return !C.getConstraintManager().isNull(C.getState(), Sym).isConstrainedTrue();
	}

	return false;
}

bool FilePointerLeakChecker::checkLeakWithExitMethod(CheckerContext& C) const {
	if (auto SP = C.getPredecessor()->getLocation().getAs<StmtPoint>()) {
		if (auto S = SP->getStmt()) {
			if (auto E = dyn_cast<Expr>(S)) {
				if (auto DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenCasts())) {
					if (auto D = DRE->getDecl()) {
						if (auto FD = dyn_cast<FunctionDecl>(D)) {
							auto Name = FD->getQualifiedNameAsString();
							if (Name == "exit" || Name == "_Exit" || Name == "abort") {
								return true;
							}
						}
					}
				}
				if (auto CE = dyn_cast<CallExpr>(E->IgnoreParenCasts())) {
					if (auto FD = CE->getDirectCallee()) {
						auto Name = FD->getQualifiedNameAsString();
						if (Name == "exit" || Name == "_Exit" || Name == "abort") {
							return true;
						}
					}
				}
			}
		}
	}

	return false;
}

void FilePointerLeakChecker::reportBug(CheckerContext& C, ProgramStateRef State, const std::vector<SymbolRef>& Syms, const std::string& Msg, const std::string& RuleID) const {
	//for (auto Sym : Syms) 
	{
		if (ExplodedNode* N = C.generateNonFatalErrorNode(State)) {
			if (!BT)
				BT.reset(new BuiltinBug(this, "FilePointerLeakChecker"));

			auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, RuleID), Msg, N);
			R->markInteresting(Syms.front());
			C.emitReport(std::move(R));
		}
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFilePointerLeakChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FilePointerLeakChecker>();
}

bool ento::shouldRegisterFilePointerLeakChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FilePointerLeakChecker>("anzu.FilePointerLeakChecker", "It is forbidden to exit without closing the file for a file pointer.", "");
}

#endif
