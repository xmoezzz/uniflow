#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FindCallExprVisitor
		: public RecursiveASTVisitor<FindCallExprVisitor> {
		std::list<const CallExpr*> StmtList;
		int Level = 0;

	public:
		const std::list<const CallExpr*>& getStmts() {
			return StmtList;
		}

	private:
		void CheckStmt(Stmt* S) {
			if (S) {
				if (auto E = dyn_cast<Expr>(S)) {
					if (auto CE = dyn_cast<CallExpr>(E->IgnoreParens())) {
						if (auto FD = CE->getDirectCallee()) {
							if (!FD->getReturnType()->isVoidType()) {
								StmtList.push_back(CE);							
							}
						}
					}
				}
			}
		}

	public:
		bool TraverseCompoundStmt(CompoundStmt* PS) {
			for (auto S : PS->children()) {
				CheckStmt(S);
			}
			return RecursiveASTVisitor<FindCallExprVisitor>::TraverseCompoundStmt(PS);
		}

		bool TraverseIfStmt(IfStmt* IS) {
			if (IS) {
				CheckStmt(IS->getThen());
				CheckStmt(IS->getElse());
			}
			return RecursiveASTVisitor<FindCallExprVisitor>::TraverseIfStmt(IS);
		}

		bool TraverseForStmt(ForStmt* FS) {
			if (FS) {
				CheckStmt(FS->getBody());
				CheckStmt(FS->getInc());
			}
			return RecursiveASTVisitor<FindCallExprVisitor>::TraverseForStmt(FS);
		}

		bool TraverseWhileStmt(WhileStmt* WS) {
			if (WS) {
				CheckStmt(WS->getBody());
			}
			return RecursiveASTVisitor<FindCallExprVisitor>::TraverseWhileStmt(WS);
		}

		bool TraverseDoStmt(DoStmt* DS) {
			if (DS) {
				CheckStmt(DS->getBody());
			}
			return RecursiveASTVisitor<FindCallExprVisitor>::TraverseDoStmt(DS);
		}

		bool TraverseCaseStmt(CaseStmt* CS) {
			if (CS) {
				CheckStmt(CS->getSubStmt());
			}
			return RecursiveASTVisitor<FindCallExprVisitor>::TraverseCaseStmt(CS);
		}
	};

	class UnusedReturnValueChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR, const std::string& Msg) const;
	};
} // end anonymous namespace

void UnusedReturnValueChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const{
	const FunctionDecl* FD = dyn_cast<FunctionDecl>(D);
	FindCallExprVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::UnusedReturnValueChecker, lang);
	for (auto CE : Stmts) {
		if (CE->getDirectCallee() && CE->getDirectCallee()->getIdentifier()) {
			std::string ce = CE->getDirectCallee()->getNameAsString();
			std::string Msg = std::vformat(fmt, std::make_format_args(ce));
			reportBug(FD, CE->getBeginLoc(), BR, Msg);
		}
	}
}

void UnusedReturnValueChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR, const std::string& Msg) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "UnusedReturnValueChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "UnusedReturnValueChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUnusedReturnValueChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UnusedReturnValueChecker>();
}

bool ento::shouldRegisterUnusedReturnValueChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UnusedReturnValueChecker>("anzu.UnusedReturnValueChecker", "Checks if the return value of a function is unused without a void cast", "");
}

#endif
