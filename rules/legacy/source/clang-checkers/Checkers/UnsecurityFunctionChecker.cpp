#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"
#include <unordered_set>

using namespace clang;
using namespace clang::ento;

namespace {
	std::unordered_set<std::string> UnsecurityFunctions = {
		"asctime", "atof", "atoi", "atol",
		"atoll", "ctime", "fopen", "freopen",
		"rewind", "setbuf", "bsearch", "fprintf",
		"fscanf", "fwprintf", "fwscanf", "getenv",
		"gmtime", "localtime", "mbsrtowcs", "mbstowcs",
		"memcpy", "memmove", "printf", "qsort",
		"setbuf", "snprintf", "sprintf", "sscanf",
		"strcat", "strcpy", "strerror", "strncat",
		"strncpy", "strtok", "swprintf", "swscanf",
		"vfprintf", "vfscanf", "vfwprintf", "vfwscanf",
		"vprintf", "vscanf", "vsnprintf", "vsprintf",
		"vsscanf", "vswprintf", "vswscanf", "vwprintf",
		"vwscanf", "wcrtomb", "wcscat", "wcscpy",
		"wcsncat", "wcsncpy", "wcsrtombs", "wcstok",
		"wcstombs", "wctomb", "wmemcpy", "wmemmove",
		"wprintf", "wscanf"
	};

	class UnsecurityFunctionChecker : public Checker<check::PreStmt<CallExpr>> {
	public:
		mutable std::unique_ptr<BuiltinBug> BT;

		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void UnsecurityFunctionChecker::checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
		const FunctionDecl* FD = C.getCalleeDecl(CE);
		if (!FD)
			return;

		if (!FD->isGlobal())
			return;

		auto Name = FD->getQualifiedNameAsString();
		if (UnsecurityFunctions.find(Name) != UnsecurityFunctions.end()) {
			reportBug(CE->getDirectCallee(), CE->getBeginLoc(), C.getBugReporter());
		}
	}

	void UnsecurityFunctionChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "UnsecurityFunctionChecker"));
		}

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::UnsecurityFunctionChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "UnsecurityFunctionChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUnsecurityFunctionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UnsecurityFunctionChecker>();
}

bool ento::shouldRegisterUnsecurityFunctionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UnsecurityFunctionChecker>("anzu.UnsecurityFunctionChecker", "", "");
}

#endif