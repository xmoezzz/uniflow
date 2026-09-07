#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class CppImplicitConversionChecker : public Checker<check::ASTDecl<CXXConversionDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const CXXConversionDecl* CD, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void CppImplicitConversionChecker::checkASTDecl(const CXXConversionDecl* CD, AnalysisManager& Mgr, BugReporter& BR) const {
	auto RD = CD->getParent();
	if (!RD)
		return;

	if (!RD->isClass())
		return;
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::CppImplicitConversionChecker, lang);
	std::string cd = CD->getNameAsString();
	std::string Msg = std::vformat(fmt, std::make_format_args(cd));

	reportBug(RD, Msg, CD->getBeginLoc(), BR);
}

void CppImplicitConversionChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "CppImplicitConversionChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CppImplicitConversionChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCppImplicitConversionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CppImplicitConversionChecker>();
}

bool ento::shouldRegisterCppImplicitConversionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CppImplicitConversionChecker>("anzu.CppImplicitConversionChecker", "Check for implicit conversions", "");
}

#endif
