#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/Decl.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class UnusedStaticFunctionChecker : public Checker<check::ASTDecl<FunctionDecl>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTDecl(const FunctionDecl* FD, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
} // end anonymous namespace

void UnusedStaticFunctionChecker::checkASTDecl(const FunctionDecl* FD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (Mgr.getASTContext().HasSyntaxErrors()) {
		return;
	}
	if (!FD->getIdentifier()) return;
	if (FD->isStatic() && !FD->isUsed() && FD->isThisDeclarationADefinition() && Mgr.isInCodeFile(FD->getLocation())) {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::UnusedStaticFunctionChecker, lang);
		std::string fd = FD->getNameAsString();
		std::string Msg = std::vformat(fmt, std::make_format_args(fd));
		reportBug(FD, Msg, FD->getLocation(), BR);
	}
}

void UnusedStaticFunctionChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "UnusedStaticFunctionChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "UnusedStaticFunctionChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUnusedStaticFunctionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UnusedStaticFunctionChecker>();
}

bool ento::shouldRegisterUnusedStaticFunctionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UnusedStaticFunctionChecker>("anzu.UnusedStaticFunctionChecker", "Checks for unused static functions", "");
}

#endif