#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FunctionVoidParamTypeChecker : public Checker<check::ASTDecl<FunctionDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const std::string& Msg, const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void FunctionVoidParamTypeChecker::checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!D)
		return;

	if (auto FD = dyn_cast<FunctionDecl>(D)) {
		if (FD->param_size() == 0) {
			if (auto FTL = FD->getFunctionTypeLoc()) {
				auto str = getSourceCode(Mgr.getASTContext(), FTL.getLParenLoc(), FTL.getRParenLoc());
				str = TrimString(str);
				if (str == "()") {
					std::string Name = FD->getIdentifier() ? FD->getName().str() : std::string();
					auto ls = anzulocalization::LocaleSetting::getInstance();
					uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
					std::string fmt = ls->parseMsgs(anzulocalization::FunctionVoidParamTypeChecker, lang);   
					std::string Msg = std::vformat(fmt, std::make_format_args(Name));
					reportBug(Msg, FD, FTL.getLParenLoc(), BR);
				}
			}
		}
	}
}

void FunctionVoidParamTypeChecker::reportBug(const std::string& Msg, const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "FunctionVoidParamTypeChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "FunctionVoidParamTypeChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFunctionVoidParamTypeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FunctionVoidParamTypeChecker>();
}

bool ento::shouldRegisterFunctionVoidParamTypeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FunctionVoidParamTypeChecker>("anzu.FunctionVoidParamTypeChecker", "When the parameter list of a function is empty, it must be explicitly declared using void.", "");
}

#endif