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
#include <unordered_map>

using namespace clang;
using namespace ento;

namespace {
	std::unordered_map<std::string, int> FileReadFuncs = {
		{"fread", 3},
	};

	std::unordered_map<std::string, int> FileWriteFuncs = {
		{"fwrite", 3},
	};

	std::unordered_map<std::string, int> FileResetFuncs = {
		{"fflush", 0},
		{"fseek", 0},
		{"fsetpos", 0},
		{"rewind", 0},
	};

	enum FILE_STREAM_STATE {
		FILE_STREAM_STATE_NONE,
		FILE_STREAM_STATE_READ,
		FILE_STREAM_STATE_WRITE,
	};

	class FileStreamReadWriteChecker : public Checker<check::PreCall,
		check::PostCall,
		check::DeadSymbols> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;
		void checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const;

	private:
		void MarkFileStream(const CallEvent& Call, CheckerContext& C, const std::unordered_map<std::string, int>& Maps, FILE_STREAM_STATE StreamState) const;
		void CheckFileStream(const CallEvent& Call, CheckerContext& C, const std::unordered_map<std::string, int>& Maps, FILE_STREAM_STATE StreamState) const;
		void reportBug(CheckerContext& C, const std::string& Msg) const;
	};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(FileStreamState, SymbolRef, FILE_STREAM_STATE)

void FileStreamReadWriteChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	CheckFileStream(Call, C, FileReadFuncs, FILE_STREAM_STATE_WRITE);
	CheckFileStream(Call, C, FileWriteFuncs, FILE_STREAM_STATE_READ);
}

void FileStreamReadWriteChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
	MarkFileStream(Call, C, FileReadFuncs, FILE_STREAM_STATE_READ);
	MarkFileStream(Call, C, FileWriteFuncs, FILE_STREAM_STATE_WRITE);
	MarkFileStream(Call, C, FileResetFuncs, FILE_STREAM_STATE_NONE);
}

void FileStreamReadWriteChecker::checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const {
	auto State = C.getState();
	auto States = State->get<FileStreamState>();
	bool AddState = false;
	for (auto& S : States) {
		auto Sym = S.first;
		if (SymReaper.isDead(Sym)) {
			State = State->remove<FileStreamState>(Sym);
			AddState = true;
		}
	}

	if (AddState) {
		C.addTransition(State);
	}
}

void FileStreamReadWriteChecker::MarkFileStream(const CallEvent& Call, CheckerContext& C, const std::unordered_map<std::string, int>& Maps, FILE_STREAM_STATE StreamState) const {
	auto D = Call.getDecl();
	if (!D)
		return;

	const FunctionDecl* FD = dyn_cast<FunctionDecl>(D);
	if (!FD)
		return;

	if (!FD->isGlobal())
		return;

	auto Name = FD->getQualifiedNameAsString();
	auto It = Maps.find(Name);
	if (It == Maps.end())
		return;

	if (It->second >= Call.getNumArgs())
		return;

	auto PosVal = Call.getArgSVal(It->second);
	if (auto Sym = PosVal.getAsSymbol()) {
		auto State = C.getState();
		State = State->set<FileStreamState>(Sym, StreamState);
		C.addTransition(State);
	}
}

void FileStreamReadWriteChecker::CheckFileStream(const CallEvent& Call, CheckerContext& C, const std::unordered_map<std::string, int>& Maps, FILE_STREAM_STATE StreamState) const {
	auto D = Call.getDecl();
	if (!D)
		return;

	const FunctionDecl* FD = dyn_cast<FunctionDecl>(D);
	if (!FD)
		return;

	if (!FD->isGlobal())
		return;

	auto Name = FD->getQualifiedNameAsString();
	auto It = Maps.find(Name);
	if (It == Maps.end())
		return;

	if (It->second >= Call.getNumArgs())
		return;

	auto PosVal = Call.getArgSVal(It->second);
	if (auto Sym = PosVal.getAsSymbol()) {
		if (auto S = C.getState()->get<FileStreamState>(Sym)) {
			if (*S == StreamState) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::FileStreamReadWriteChecker, lang); 
				reportBug(C, Msg);
				return;
			}
		}
	}
}

void FileStreamReadWriteChecker::reportBug(CheckerContext& C, const std::string& Msg) const {
	if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
		if (!BT)
			BT.reset(new BuiltinBug(this, "FileStreamReadWriteChecker"));

		auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "FileStreamReadWriteChecker"), Msg, N);
		C.emitReport(std::move(R));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFileStreamReadWriteChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FileStreamReadWriteChecker>();
}

bool ento::shouldRegisterFileStreamReadWriteChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FileStreamReadWriteChecker>("anzu.FileStreamReadWriteChecker", "", "");
}

#endif
