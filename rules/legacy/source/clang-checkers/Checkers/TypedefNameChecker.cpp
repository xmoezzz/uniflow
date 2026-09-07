#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

#include <set>

using namespace clang;
using namespace clang::ento;

namespace {
	class TypedefNameChecker : public Checker<check::ASTDecl<VarDecl>, check::ASTDecl<TypedefDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;
		mutable std::set<StringRef> TypedefNames;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void checkASTDecl(const TypedefDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void TypedefNameChecker::checkASTDecl(const TypedefDecl* TD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (TD)
		TypedefNames.insert(TD->getName());
}

void TypedefNameChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!VD)
		return;

	std::string Name = VD->getNameAsString();
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::TypedefNameChecker, lang);
	if (TypedefNames.find(Name) != TypedefNames.end()) {
		std::string Msg = std::vformat(fmt, std::make_format_args(Name));
		reportBug(findFunctionDecl(VD), Msg, VD->getBeginLoc(), BR);
	}
}

void TypedefNameChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "TypedefNameChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "TypedefNameChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerTypedefNameChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<TypedefNameChecker>();
}

bool ento::shouldRegisterTypedefNameChecker(const CheckerManager& mgr) {
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
	registry.addChecker<TypedefNameChecker>("anzu.TypedefNameChecker", "Prohibit variable names that match typedef names", "");
}

#endif