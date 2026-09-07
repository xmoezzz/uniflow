#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Decl.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class LimitFunctionParametersChecker : public Checker<check::ASTDecl<FunctionDecl>> {
		mutable std::unique_ptr<BugType> BT;
		static const int MAX_PARAMETERS = 20; // 最大参数数量限制

	public:
		void checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void LimitFunctionParametersChecker::checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	int paramCount = D->getNumParams();

	if (paramCount > MAX_PARAMETERS) {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::LimitFunctionParametersChecker, lang);
		std::string Msg = std::vformat(fmt, std::make_format_args(paramCount, MAX_PARAMETERS));

		reportBug(D, Msg, D->getBeginLoc(), BR);
	}
}

void LimitFunctionParametersChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "LimitFunctionParametersChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "LimitFunctionParametersChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerLimitFunctionParametersChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<LimitFunctionParametersChecker>();
}

bool ento::shouldRegisterLimitFunctionParametersChecker(const CheckerManager& mgr) {
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
	registry.addChecker<LimitFunctionParametersChecker>("anzu.LimitFunctionParametersChecker", "", "");
}

#endif