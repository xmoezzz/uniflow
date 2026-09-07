#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class ExternVarHasInitChecker : public Checker<check::ASTDecl<VarDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const std::string& Msg, const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void ExternVarHasInitChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!VD || !VD->hasExternalStorage() || !VD->hasInit())
		return;

	if (auto Init = VD->getInit()) {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string vd = VD->getName().str();
		std::string fmt = ls->parseMsgs(anzulocalization::ExternVarHasInitChecker, lang);
		std::string Msg = std::vformat(fmt, std::make_format_args(vd));
		reportBug(Msg, findFunctionDecl(VD), Init->getBeginLoc(), BR);
	}
}

void ExternVarHasInitChecker::reportBug(const std::string& Msg, const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ExternVarHasInitChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ExternVarHasInitChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
	}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerExternVarHasInitChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ExternVarHasInitChecker>();
}

bool ento::shouldRegisterExternVarHasInitChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ExternVarHasInitChecker>("anzu.ExternVarHasInitChecker", "It is prohibited to use the extern declaration to initialize variables.", "");
}

#endif