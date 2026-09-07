#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"
#include <unordered_map>

using namespace clang;
using namespace ento;

namespace {
	class FindLoopCondConstExprVisitor
		: public RecursiveASTVisitor<FindLoopCondConstExprVisitor> {
		std::list<const Expr*> ExprList;

	public:
		const std::list<const Expr*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitWhileStmt(const WhileStmt* WS) {
			if (IsConstantCond(WS->getCond())) {
				ExprList.push_back(WS->getCond());
			}
			return true;
		}

		bool VisitDoStmt(const DoStmt* DS) {
			if (IsConstantCond(DS->getCond())) {
				ExprList.push_back(DS->getCond());
			}
			return true;
		}

		bool VisitForStmt(const ForStmt* FS) {
			if (IsConstantCond(FS->getCond())) {
				ExprList.push_back(FS->getCond());
			}
			return true;
		}

	private:
		bool IsConstantCond(const Expr* E) {
			if (!E) return false;
			E = E->IgnoreParenImpCasts();
			if (isa<IntegerLiteral>(E) ||
				isa<FixedPointLiteral>(E) ||
				isa<CharacterLiteral>(E) ||
				isa<FloatingLiteral>(E) ||
				isa<ImaginaryLiteral>(E) ||
				isa<StringLiteral>(E) ||
				isa<CXXBoolLiteralExpr>(E)) {
				return true;
			}

			return false;
		}
	};

	class LoopCondConstantChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void LoopCondConstantChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	auto FD = dyn_cast<FunctionDecl>(D);
	FindLoopCondConstExprVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Exprs = Visitor.getExprs();
	for (auto E : Exprs) {
		reportBug(FD, E->getBeginLoc(), BR);
	}
}

void LoopCondConstantChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;

	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "LoopCondConstantChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::LoopCondConstantChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "LoopCondConstantChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerLoopCondConstantChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<LoopCondConstantChecker>();
}

bool ento::shouldRegisterLoopCondConstantChecker(const CheckerManager& mgr) {
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
	registry.addChecker<LoopCondConstantChecker>("anzu.LoopCondConstantChecker", "Use infinite loop statements with caution.", "");
}

#endif