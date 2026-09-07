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
#include <unordered_set>

using namespace clang;
using namespace clang::ento;
using namespace clang::ast_matchers;

namespace {
	class EnumElementRepValueChecker : public Checker<check::ASTDecl<EnumDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const EnumDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			std::unordered_set<int64_t> Values;
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::EnumElementRepValueChecker, lang);
			for (const EnumConstantDecl* ECD : D->enumerators()) {
				auto V = ECD->getInitVal().getExtValue();
				if (Values.find(V) != Values.end()) {
					auto FD = findFunctionDecl(D);
					reportBug(FD, Msg, ECD->getBeginLoc(), BR);
					break;
				}
				Values.insert(V);
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "EnumElementRepValueChecker"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "EnumElementRepValueChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerEnumElementRepValueChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<EnumElementRepValueChecker>();
}

bool ento::shouldRegisterEnumElementRepValueChecker(const CheckerManager& mgr) {
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
	registry.addChecker<EnumElementRepValueChecker>("anzu.EnumElementRepValueChecker", "", "");
}

#endif
