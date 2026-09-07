#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/Decl.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class AvoidParamNameInProtoChecker : public Checker<check::ASTDecl<FunctionDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;
	public:
		void checkASTDecl(const FunctionDecl* FD, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void AvoidParamNameInProtoChecker::checkASTDecl(const FunctionDecl* FD,
	AnalysisManager& Mgr,
	BugReporter& BR) const {
	// Only check function declarations, not definitions
	if (FD->isThisDeclarationADefinition()) {
		return;
	}

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::AvoidParamNameInProtoChecker, lang);
	for (const auto* PVD : FD->parameters()) {
		if (!PVD->getName().empty()) {
			std::string pvd = PVD->getNameAsString();
			std::string Msg = std::vformat(fmt, std::make_format_args(pvd));
			reportBug(FD, Msg, PVD->getBeginLoc(), BR);
		}
	}
}

void AvoidParamNameInProtoChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "AvoidParamNameInProtoChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "AvoidParamNameInProtoChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAvoidParamNameInProtoChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<AvoidParamNameInProtoChecker>();
}

bool ento::shouldRegisterAvoidParamNameInProtoChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::C);
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
	registry.addChecker<AvoidParamNameInProtoChecker>("anzu.AvoidParamNameInProtoChecker", "", "");
}

#endif