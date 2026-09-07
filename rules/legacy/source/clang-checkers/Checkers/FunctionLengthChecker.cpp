#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Decl.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FunctionLengthChecker : public Checker<check::ASTDecl<FunctionDecl>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void FunctionLengthChecker::checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	const unsigned MaxLines = 200; // maximum allowed lines in a function

	SourceManager& SM = Mgr.getASTContext().getSourceManager();
	SourceLocation StartLoc = SM.getExpansionLoc(D->getBeginLoc());
	SourceLocation EndLoc = SM.getExpansionLoc(D->getEndLoc());

	unsigned Lines = SM.getExpansionLineNumber(EndLoc) - SM.getExpansionLineNumber(StartLoc);

	if (Lines > MaxLines) {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::FunctionLengthChecker, lang);
		std::string l = std::to_string(Lines);
		std::string ml = std::to_string(MaxLines);
		std::string Msg = std::vformat(fmt, std::make_format_args(l, ml));
		reportBug(D, Msg, D->getBeginLoc(), BR);
	}
}

void FunctionLengthChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "FunctionLengthChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "FunctionLengthChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFunctionLengthChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FunctionLengthChecker>();
}

bool ento::shouldRegisterFunctionLengthChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FunctionLengthChecker>("anzu.FunctionLengthChecker", "", "");
}

#endif