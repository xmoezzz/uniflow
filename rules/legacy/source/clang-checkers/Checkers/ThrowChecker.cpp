#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtCXX.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
	class FindThrowExprVisitor
		: public RecursiveASTVisitor<FindThrowExprVisitor> {
		std::list<const CXXThrowExpr*> ExprList;

	public:
		const std::list<const CXXThrowExpr*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitCXXThrowExpr(const CXXThrowExpr* TE) {
			if (TE) {
				ExprList.push_back(TE);
			}
			return true;
		}
	};

	class ThrowChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const
		{
			FindThrowExprVisitor Visitor;
			Visitor.TraverseDecl(const_cast<Decl*>(D));
			auto Exprs = Visitor.getExprs();
			for (auto TE : Exprs) {
				if (!checkInvalidThrow(TE)) {
					reportBug(D, TE->getBeginLoc(), BR);
				}
			}
		}

		bool checkInvalidThrow(const CXXThrowExpr* TE) const {
			if (TE) {
				if (auto Expr = TE->getSubExpr()) {
					if (Expr->IgnoreParenImpCasts()->getType()->isPointerType()) {
						return false;
					}
				}
			}

			return true;
		}

		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "ThrowChecker"));

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::ThrowChecker, lang);       
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "ThrowChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end of anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerThrowChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ThrowChecker>();
}

bool ento::shouldRegisterThrowChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ThrowChecker>("anzu.ThrowChecker", "", "");
}

#endif
