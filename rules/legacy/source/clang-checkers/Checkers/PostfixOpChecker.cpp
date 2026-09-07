#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/StmtCXX.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class PostfixOpChecker : public Checker<check::ASTCodeBody, check::ASTDecl<CXXRecordDecl>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const {
			const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);
			if (!FD || 2 != FD->getNumParams())
				return;

			auto Name = FD->getNameAsString();
			if (Name == "operator++" ||
				Name == "operator--") {
				if (!FD->getReturnType().isConstQualified()) {
					reportBug(FD, FD->getBeginLoc(), BR);
				}
			}
		}

		void checkASTDecl(const CXXRecordDecl* RD, AnalysisManager& mgr,
			BugReporter& BR) const {
			if (!RD || !RD->hasDefinition())
				return;

			for (const CXXMethodDecl* MD : RD->methods()) {
				if (MD->isOverloadedOperator()) {
					OverloadedOperatorKind OOK = MD->getOverloadedOperator();

					if ((OOK == OO_PlusPlus || OOK == OO_MinusMinus) &&
						MD->param_size() == 1 &&
						!MD->getReturnType().isConstQualified()) {

						reportBug(MD, MD->getBeginLoc(), BR);
					}
				}
			}
		}

	private:
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
					
			if (!BT)
				BT.reset(new BuiltinBug(this, "PostfixOpChecker"));

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::PostfixOpChecker, lang);       
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT,
				Msg,
				createRuleExtData(1, "PostfixOpChecker"),
				DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end of anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPostfixOpChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PostfixOpChecker>();
}

bool ento::shouldRegisterPostfixOpChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PostfixOpChecker>("anzu.PostfixOpChecker", "", "");
}

#endif
