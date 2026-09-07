#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;
using namespace clang::ast_matchers;

namespace {
	class EnumInitializationChecker2 : public Checker<check::ASTDecl<EnumDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const EnumDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			auto FD = findFunctionDecl(D);
			int InitCount = 0;
			int Count = 0;
			bool IsFirst = true;
			bool FirstInit = false;

			for (const EnumConstantDecl* ECD : D->enumerators()) {
				if (ECD->getInitExpr()) {
					++InitCount;
				}
				if (IsFirst) {
					IsFirst = false;
					FirstInit = !!ECD->getInitExpr();
				}
				++Count;
			}

			if (Count != InitCount) {
				if (1 != InitCount || !FirstInit) {
					auto ls = anzulocalization::LocaleSetting::getInstance();
					uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
					std::string Msg = ls->parseMsgs(anzulocalization::EnumInitializationChecker2, lang);
					reportBug(FD, Msg, D->getBeginLoc(), BR);
				}
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "EnumInitializationChecker2"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "EnumInitializationChecker2"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerEnumInitializationChecker2(CheckerManager& Mgr) {
	Mgr.registerChecker<EnumInitializationChecker2>();
}

bool ento::shouldRegisterEnumInitializationChecker2(const CheckerManager& mgr) {
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
	registry.addChecker<EnumInitializationChecker2>("anzu.EnumInitializationChecker2", "", "");
}

#endif
