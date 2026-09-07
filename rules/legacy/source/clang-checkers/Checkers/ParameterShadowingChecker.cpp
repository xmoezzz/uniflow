#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class ParameterShadowingChecker : public Checker<check::ASTDecl<ParmVarDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const ParmVarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;

	private:
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void ParameterShadowingChecker::checkASTDecl(const ParmVarDecl* PVD, AnalysisManager& Mgr, BugReporter& BR) const {
	const DeclContext* DC = PVD->getDeclContext();
	IdentifierInfo* II = PVD->getIdentifier();
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::ParameterShadowingChecker, lang);

	if (auto Parent = DC->getParent()) {
		// Iterate through global context to find shadowing
		for (const auto& D : Parent->decls())
			if (const auto* OuterVD = dyn_cast_or_null<VarDecl>(D))
				if (OuterVD->getIdentifier() == II && OuterVD->hasGlobalStorage()) {
					std::string name = II->getName().str();
					std::string Msg = std::vformat(fmt, std::make_format_args(name));
					reportBug(findFunctionDecl(PVD), Msg, PVD->getBeginLoc(), BR);
					return;
				}
	}
}

void ParameterShadowingChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ParameterShadowingChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ParameterShadowingChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerParameterShadowingChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ParameterShadowingChecker>();
}

bool ento::shouldRegisterParameterShadowingChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ParameterShadowingChecker>("anzu.ParameterShadowingChecker", "Prohibit function parameters from shadowing global variables", "");
}

#endif