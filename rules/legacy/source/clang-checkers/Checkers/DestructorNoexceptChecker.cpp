#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/AST/StmtCXX.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {

	class DestructorNoexceptChecker : public Checker<check::ASTDecl<CXXDestructorDecl>, check::ASTDecl<FunctionDecl>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTDecl(const CXXDestructorDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			const auto* Proto = dyn_cast_or_null<FunctionProtoType>(D->getType()->getAs<FunctionType>());
			if (Proto && !Proto->isNothrow()) {
				reportBug(D, D->getBeginLoc(), BR);
			}
		}

		void checkASTDecl(const FunctionDecl* F, AnalysisManager& Mgr, BugReporter& BR) const {
			if (F->getOverloadedOperator() == OO_Delete || F->getOverloadedOperator() == OO_Array_Delete) {
				const auto* Proto = dyn_cast_or_null<FunctionProtoType>(F->getType()->getAs<FunctionType>());
				if (Proto && !Proto->isNothrow()) {
					reportBug(F, F->getBeginLoc(), BR);
				}
			}
		}

		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "DestructorNoexceptChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::DestructorNoexceptChecker, lang);
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "DestructorNoexceptChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end of anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDestructorNoexceptChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<DestructorNoexceptChecker>();
}

bool ento::shouldRegisterDestructorNoexceptChecker(const CheckerManager& mgr) {
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
	registry.addChecker<DestructorNoexceptChecker>("anzu.DestructorNoexceptChecker", "", "");
}

#endif
