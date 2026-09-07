#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class VariableShadowingChecker : public Checker<check::ASTDecl<VarDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;

	private:
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void VariableShadowingChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (Mgr.getASTContext().HasSyntaxErrors()) {
		return;
	}
	if (VD->hasGlobalStorage() || VD->isStaticDataMember())
		return;

	const DeclContext* DC = VD->getDeclContext();
	IdentifierInfo* II = VD->getIdentifier();

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::VariableShadowingChecker, lang);
	// Iterate through outer contexts to find shadowing
	while ((DC = DC->getParent()))
		for (const auto& D : DC->decls())
			if (const auto* OuterVD = dyn_cast_or_null<VarDecl>(D))
				if (OuterVD->getIdentifier() == II && OuterVD->hasGlobalStorage()) {
					std::string name = II->getName().str();
					std::string Msg = std::vformat(fmt, std::make_format_args(name));
					reportBug(findFunctionDecl(VD), Msg, VD->getBeginLoc(), BR);
					//return;
				}
}

void VariableShadowingChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "VariableShadowingChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "VariableShadowingChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerVariableShadowingChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<VariableShadowingChecker>();
}

bool ento::shouldRegisterVariableShadowingChecker(const CheckerManager& mgr) {
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
	registry.addChecker<VariableShadowingChecker>("anzu.VariableShadowingChecker", "Prohibit local variables from shadowing global variables", "");
}

#endif