#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Decl.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class AvoidProceduresAsParametersChecker : public Checker<check::ASTDecl<FunctionDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;
	public:
		void checkASTDecl(const FunctionDecl* FD, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void AvoidProceduresAsParametersChecker::checkASTDecl(const FunctionDecl* FD, AnalysisManager& Mgr, BugReporter& BR) const {
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::AvoidProceduresAsParametersChecker, lang);
	for (const ParmVarDecl* P : FD->parameters()) {
		QualType T = P->getType();
		if (T->isFunctionPointerType() || T->isMemberFunctionPointerType()) {
			reportBug(FD, Msg, P->getBeginLoc(), BR);
		}
	}
}

void AvoidProceduresAsParametersChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (Loc.isMacroID())
		return;

	if (!BT)
		BT.reset(new BuiltinBug(this, "AvoidProceduresAsParametersChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "AvoidProceduresAsParametersChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAvoidProceduresAsParametersChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<AvoidProceduresAsParametersChecker>();
}

bool ento::shouldRegisterAvoidProceduresAsParametersChecker(const CheckerManager& mgr) {
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
	registry.addChecker<AvoidProceduresAsParametersChecker>("anzu.AvoidProceduresAsParametersChecker", "", "");
}

#endif