#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/Decl.h"
#include "../Utils.h"
#include <list>

using namespace clang;
using namespace clang::ento;

namespace {
	class MainFileNotUseFuncChecker : public Checker<check::ASTDecl<FunctionDecl>, check::EndOfTranslationUnit> {
		mutable std::unique_ptr<BugType> BT;
		mutable bool IsMainFile = false;
		mutable std::list<const FunctionDecl*> FDS;

	public:
		void checkASTDecl(const FunctionDecl* FD, AnalysisManager& Mgr, BugReporter& BR) const;

		void checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
			AnalysisManager& mgr,
			BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
} // end anonymous namespace

void MainFileNotUseFuncChecker::checkASTDecl(const FunctionDecl* FD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (FD->isMain()) {
		IsMainFile = true;
		return;
	}

	if (!FD->isUsed() && FD->isThisDeclarationADefinition() && Mgr.isInCodeFile(FD->getLocation())) {
		FDS.push_back(FD);
	}
}

void MainFileNotUseFuncChecker::checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
	AnalysisManager& mgr,
	BugReporter& BR) const {
	if (!IsMainFile) {
		return;
	}
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::MainFileNotUseFuncChecker, lang);

	for (auto FD : FDS) {
		if (!FD->getIdentifier()) continue;

		std::string fd = FD->getNameAsString();
		std::string Msg = std::vformat(fmt, std::make_format_args(fd));
		reportBug(FD, Msg, FD->getLocation(), BR);
	}
}

void MainFileNotUseFuncChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "MainFileNotUseFuncChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "MainFileNotUseFuncChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMainFileNotUseFuncChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MainFileNotUseFuncChecker>();
}

bool ento::shouldRegisterMainFileNotUseFuncChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MainFileNotUseFuncChecker>("anzu.MainFileNotUseFuncChecker", "Checks for main file unused functions", "");
}

#endif