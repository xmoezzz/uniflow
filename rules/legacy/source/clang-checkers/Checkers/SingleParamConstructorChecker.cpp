#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/DeclCXX.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class SingleParamConstructorChecker : public Checker<check::ASTDecl<CXXConstructorDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const CXXConstructorDecl* D, AnalysisManager& Mgr,
			BugReporter& BR) const {
			// Ignore invalid code.
			if (D->isInvalidDecl()) {
				return;
			}

			// Check for a single parameter.
			if (D->getNumParams() == 1) {
				// If it's not marked explicit, report it.
				if (!D->isExplicit()) {
					auto ls = anzulocalization::LocaleSetting::getInstance();
					uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
					std::string Msg = ls->parseMsgs(anzulocalization::SingleParamConstructorChecker, lang);
					reportBug(D, Msg, D->getBeginLoc(), BR);
				}
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "SingleParamConstructorChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "SingleParamConstructorChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSingleParamConstructorChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SingleParamConstructorChecker>();
}

bool ento::shouldRegisterSingleParamConstructorChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SingleParamConstructorChecker>("anzu.SingleParamConstructorChecker", "", "");
}

#endif
