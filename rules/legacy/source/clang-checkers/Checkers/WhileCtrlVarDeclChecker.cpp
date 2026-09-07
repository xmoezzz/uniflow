#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindDeclRefExprVisitor
		: public RecursiveASTVisitor<FindDeclRefExprVisitor> {
		std::list<const DeclRefExpr*> StmtList;

	public:
		const std::list<const DeclRefExpr*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitDeclRefExpr(const DeclRefExpr* DRE) {
			if (DRE) {
				StmtList.push_back(DRE);
			}
			return true;
		}
	};

	class FindWhileCondExprVisitor
		: public RecursiveASTVisitor<FindWhileCondExprVisitor> {
		std::list<std::pair<const Expr*, const Expr*>> StmtList;

	public:
		const std::list<std::pair<const Expr*, const Expr*>>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitWhileStmt(const WhileStmt* WS) {
			if (auto Cond = WS->getCond()) {
				StmtList.push_back(std::make_pair(Cond, (const Expr*)nullptr));
			}
			return true;
		}

		bool VisitForStmt(const ForStmt* FS) {
			if (auto Cond = FS->getCond()) {
				StmtList.push_back(std::make_pair(Cond, FS->getInc()));
			}
			return true;
		}

		bool VisitDoStmt(const DoStmt* DS) {
			if (auto Cond = DS->getCond()) {
				StmtList.push_back(std::make_pair(Cond, (const Expr*)nullptr));
			}
			return true;
		}
	};

	class WhileCtrlVarDeclChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		const DeclRefExpr* findGlobalCtrlVar(const Expr* Cond, const Expr* Inc) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void WhileCtrlVarDeclChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	const FunctionDecl* FD = dyn_cast<FunctionDecl>(D);
	FindWhileCondExprVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto S : Stmts) {		
		if (auto DRE = findGlobalCtrlVar(S.first, S.second)) {
			reportBug(FD, DRE->getBeginLoc(), BR);
		}
	}
}
const DeclRefExpr* WhileCtrlVarDeclChecker::findGlobalCtrlVar(const Expr* Cond, const Expr* Inc) const {
	if (!Cond)
		return nullptr;

	if (auto DRE = dyn_cast<DeclRefExpr>(Cond->IgnoreParenCasts())) {
		if (auto D = DRE->getDecl()) {
			if (auto VD = dyn_cast<VarDecl>(D)) {
				if (!VD->isLocalVarDeclOrParm()) {
					return DRE;
				}
			}
		}
	}
	else if (auto UO = dyn_cast<UnaryOperator>(Cond->IgnoreParenCasts())) {
		if (UO->getOpcode() == UnaryOperator::Opcode::UO_LNot ||
			UO->getOpcode() == UnaryOperator::Opcode::UO_Deref) {
			if (auto DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenCasts())) {
				if (auto D = DRE->getDecl()) {
					if (auto VD = dyn_cast<VarDecl>(D)) {
						if (!VD->isLocalVarDeclOrParm()) {
							return DRE;
						}
					}
				}
			}
		}
	}
	else if (auto BO = dyn_cast<BinaryOperator>(Cond->IgnoreParenCasts())) {
		const Decl* CD = nullptr;
		if (Inc) {
			if (auto UO = dyn_cast<UnaryOperator>(Inc->IgnoreParenCasts())) {
				if (UO->isIncrementDecrementOp()) {
					if (auto DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenCasts())) {
						CD = DRE->getDecl();
					}
				}
			}
			if (auto BO = dyn_cast<BinaryOperator>(Inc->IgnoreParenCasts())) {
				if (BO->isAssignmentOp()) {
					if (auto DRE = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenCasts())) {
						CD = DRE->getDecl();
					}
				}
			}
		}

		FindDeclRefExprVisitor Visitor;
		Visitor.TraverseStmt((Stmt*)Cond);
		auto DREs = Visitor.getStmts();
		if (DREs.empty())
			return nullptr;

		for (auto DRE : DREs) {
			if (auto D = DRE->getDecl()) {
				if (auto VD = dyn_cast<VarDecl>(D)) {
					if (VD->isLocalVarDeclOrParm()) {
						return nullptr;
					}
				}
			}
		}

		if (CD) {
			for (auto DRE : DREs) {
				if (CD == DRE->getDecl()) {
					return DRE;
				}
			}
		}

		if (auto DRE = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenCasts())) {
			return DRE;
		}

		if (auto DRE = dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreParenCasts())) {
			return DRE;
		}
				
		return DREs.front();
	}

	return nullptr;
}

void WhileCtrlVarDeclChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "WhileCtrlVarDeclChecker"));
	}

	// Report the issue        
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::WhileCtrlVarDeclChecker, lang);	
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "WhileCtrlVarDeclChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerWhileCtrlVarDeclChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<WhileCtrlVarDeclChecker>();
}

bool ento::shouldRegisterWhileCtrlVarDeclChecker(const CheckerManager& mgr) {
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
	registry.addChecker<WhileCtrlVarDeclChecker>("anzu.WhileCtrlVarDeclChecker", "The control variable of a for loop must be a local variable.", "");
}

#endif