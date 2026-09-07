#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
	class RawPointerCopyChecker : public Checker<check::ASTDecl<CXXRecordDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const CXXRecordDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void RawPointerCopyChecker::checkASTDecl(const CXXRecordDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!D->isThisDeclarationADefinition())
		return;

	if (!D->hasDefinition())
		return;
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::RawPointerCopyChecker, lang);
	for (const auto* FD : D->fields()) {
		QualType QT = FD->getType();
		if (QT->isPointerType()) {
			if (!D->hasUserDeclaredCopyConstructor() && !D->hasUserDeclaredCopyAssignment()) {
				std::string name = D->getNameAsString();
				std::string Msg = std::vformat(fmt, std::make_format_args(name));

				reportBug(D, Msg, D->getBeginLoc(), BR);
				return;
			}
		}
	}
}

void RawPointerCopyChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "RawPointerCopyChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "RawPointerCopyChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerRawPointerCopyChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<RawPointerCopyChecker>();
}

bool ento::shouldRegisterRawPointerCopyChecker(const CheckerManager& mgr) {
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
	registry.addChecker<RawPointerCopyChecker>("anzu.RawPointerCopyChecker", "", "");
}

#endif
