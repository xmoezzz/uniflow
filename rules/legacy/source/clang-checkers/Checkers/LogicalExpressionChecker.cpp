#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindIfStmtCondVisitor
		: public RecursiveASTVisitor<FindIfStmtCondVisitor> {
		std::list<const Expr*> ExprList;

	public:
		const std::list<const Expr*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitIfStmt(const IfStmt* IS) {
			if (auto C = IS->getCond()) {
				ExprList.push_back(C);
			}
			return true;
		}
	};

	class LogicalExpressionChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const {
			auto IsCpp = Mgr.getASTContext().getLangOpts().CPlusPlus;
			auto FD = dyn_cast<FunctionDecl>(D);
			FindIfStmtCondVisitor Visitor;
			Visitor.TraverseDecl(const_cast<Decl*>(D));
			auto Exprs = Visitor.getExprs();
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::LogicalExpressionChecker, lang);
			for (auto E : Exprs) {
				const Expr* Condition = E->IgnoreParenImpCasts();
				auto QT = Condition->getType();
				if (IsCpp) {
					if (!QT->isBooleanType()) {
						if (QT->isIntegralOrEnumerationType() || QT->isFloatingType()) {
							reportBug(FD, Msg, Condition->getBeginLoc(), BR);
						}
					}
				}
				else {
					if (!QT->isIntegerType()) {
						reportBug(FD, Msg, Condition->getBeginLoc(), BR);
					}
				}
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "LogicalExpressionChecker"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "LogicalExpressionChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerLogicalExpressionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<LogicalExpressionChecker>();
}

bool ento::shouldRegisterLogicalExpressionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<LogicalExpressionChecker>("anzu1.LogicalExpressionChecker", "Checks if expressions in if statements are logical", "");
}

#endif