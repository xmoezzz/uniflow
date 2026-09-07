#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"
#include <unordered_map>

using namespace clang;
using namespace clang::ento;

namespace {
	struct FunctionInfo
	{
		int ParamNum{ -1 };
		std::string RuleIds;
	};

	std::unordered_map<std::string, FunctionInfo> FunctionMap =
	{
		{"atoi", {-1, "DisableFunctionChecker.AtoX"}},
		{"atol", {-1, "DisableFunctionChecker.AtoX"}},
		{"atoll", {-1, "DisableFunctionChecker.AtoX"}},
		{"itoa", {-1, "DisableFunctionChecker.XtoA"}},
		{"IsBadWritePtr", {2, "DisableFunctionChecker.IsBadWritePtr"}},
		{"alloca", {-1, "DisableFunctionChecker.Alloca"}},
		{"_alloca", {-1, "DisableFunctionChecker.Alloca"}},
		{"gets", {-1, "DisableFunctionChecker.Gets"}},
		{"std::terminate", {-1, "DisableFunctionChecker.StdTerm"}},
		{"std::abort", {-1, "DisableFunctionChecker.StdTerm"}},
		{"std::_Exit", {-1, "DisableFunctionChecker.StdTerm"}},
		{"pthread_kill", {-1, "DisableFunctionChecker.ThreadKill"}},
		{"TerminateThread", {2, "DisableFunctionChecker.Terminate"}},
		{"TerminateProcess", {2, "DisableFunctionChecker.Terminate"}},
		{"system", {-1, "DisableFunctionChecker.System"}},
		{"longjmp", {-1, "DisableFunctionChecker.Jmp"}},
		{"setjmp", {-1, "DisableFunctionChecker.Jmp"}},
		{"exit", {-1, "DisableFunctionChecker.Exit"}},
		{"abort", {-1, "DisableFunctionChecker.Exit"}},
		{"CharToOem", {-1, "DisableFunctionChecker.CharToOem"}},
		{"CharToOemA", {-1, "DisableFunctionChecker.CharToOem"}},
		{"CharToOemW", {-1, "DisableFunctionChecker.CharToOem"}},
		{"_splitpath", {-1, "DisableFunctionChecker.Path"}},
		{"_makepath", {-1, "DisableFunctionChecker.Path"}},
		{"scanf", {-1, "DisableFunctionChecker.Scanf"}},
		{"strtok", {-1, "DisableFunctionChecker.Strtok"}},
		{"ChangeWindowMessageFilter", {2, "DisableFunctionChecker.ChangeWindowMessageFilter"}},
		{"execlp", {-1, "DisableFunctionChecker.Exec"}},
		{"seteuid", {-1, "DisableFunctionChecker.SetId"}},
		{"setegid", {-1, "DisableFunctionChecker.SetId"}},
		{"getlogin", {-1, "DisableFunctionChecker.GetLogin"}},
		{"memcpy", {-1, "DisableFunctionChecker.Memcpy"}},
	};

	class DisableFunctionChecker : public Checker<check::PreStmt<CallExpr>> {
	public:
		mutable std::unique_ptr<BuiltinBug> BT;

		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const std::string& RuleId, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void DisableFunctionChecker::checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
		const FunctionDecl* FD = C.getCalleeDecl(CE);
		if (!FD)
			return;

		if (!FD->isGlobal())
			return;

		auto Name = FD->getQualifiedNameAsString();
		auto It = FunctionMap.find(Name);
		if (It == FunctionMap.end())
			return;

		if (It->second.ParamNum != -1 &&
			It->second.ParamNum != FD->getNumParams())
			return;
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::DisableFunctionChecker, lang);
		std::string Msg = std::vformat(fmt, std::make_format_args(Name));
		reportBug(CE->getDirectCallee(), Msg, It->second.RuleIds, CE->getBeginLoc(), C.getBugReporter());
	}

	void DisableFunctionChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const std::string& RuleId, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "DisableFunctionChecker"));
		}

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, RuleId), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDisableFunctionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<DisableFunctionChecker>();
}

bool ento::shouldRegisterDisableFunctionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<DisableFunctionChecker>("anzu1.DisableFunctionChecker", "", "");
}

#endif