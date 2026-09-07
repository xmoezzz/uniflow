#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class DefaultArgInVirtualFuncChecker : public Checker<check::ASTDecl<CXXMethodDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const CXXMethodDecl* MD, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void DefaultArgInVirtualFuncChecker::checkASTDecl(const CXXMethodDecl* MD, AnalysisManager& Mgr, BugReporter& BR) const {
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::DefaultArgInVirtualFuncChecker, lang);
	if (MD->isVirtual()) {
		for (unsigned I = 0, E = MD->getNumParams(); I != E; ++I) {
			if (auto PD = MD->getParamDecl(I)) {
				if (auto DAE = PD->getDefaultArg()) {
					std::string md = MD->getNameAsString();
					std::string Message = std::vformat(fmt, std::make_format_args(md));

					reportBug(MD, Message, DAE->getBeginLoc(), BR);
				}
			}
		}
	}
}

void DefaultArgInVirtualFuncChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "DefaultArgInVirtualFuncChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "DefaultArgInVirtualFuncChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDefaultArgInVirtualFuncChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<DefaultArgInVirtualFuncChecker>();
}

bool ento::shouldRegisterDefaultArgInVirtualFuncChecker(const CheckerManager& mgr) {
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
	registry.addChecker<DefaultArgInVirtualFuncChecker>("anzu.DefaultArgInVirtualFuncChecker", "", "");
}

#endif
