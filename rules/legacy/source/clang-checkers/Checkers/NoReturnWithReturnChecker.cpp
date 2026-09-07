#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Attr.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class NoReturnWithReturnChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);
			if (!FD || !FD->hasAttr<NoReturnAttr>() || !FD->getBody()) {
				return;
			}

			for (const Stmt* S : FD->getBody()->children()) {
				if (const ReturnStmt* RS = llvm::dyn_cast_or_null<ReturnStmt>(S)) {
					reportBug(FD, RS->getBeginLoc(), BR);
				}
			}
		}

		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "NoReturnWithReturnChecker"));

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::NoReturnWithReturnChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "NoReturnWithReturnChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end of anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerNoReturnWithReturnChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<NoReturnWithReturnChecker>();
}

bool ento::shouldRegisterNoReturnWithReturnChecker(const CheckerManager& mgr) {
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
	registry.addChecker<NoReturnWithReturnChecker>("anzu.NoReturnWithReturnChecker", "", "");
}

#endif
