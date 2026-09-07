#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"
#include <set>

using namespace clang;
using namespace ento;

namespace {
	class FindForStmtVisitor
		: public RecursiveASTVisitor<FindForStmtVisitor> {
		std::list<const ForStmt*> StmtList;

	public:
		const std::list<const ForStmt*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitForStmt(const ForStmt* FS) {
			if (FS) {
				StmtList.push_back(FS);
			}
			return true;
		}
	};

	class FindLoopCtrlVarDeclVisitor
		: public RecursiveASTVisitor<FindLoopCtrlVarDeclVisitor> {
		std::set<const VarDecl*> DeclList;

	public:
		const std::set<const VarDecl*>& getDecls() {
			return DeclList;
		}

	public:
		bool VisitUnaryOperator(const UnaryOperator* UO) {
			if (UO && UO->isIncrementDecrementOp()) {
				if (auto Sub = UO->getSubExpr()) {
					if (auto DRE = dyn_cast<DeclRefExpr>(Sub->IgnoreParenImpCasts())) {
						if (auto D = DRE->getDecl()) {
							if (auto VD = dyn_cast<VarDecl>(D)) {
								DeclList.insert(VD);
							}
						}
					}
				}
			}
			return true;
		}

		bool VisitBinaryOperator(const BinaryOperator* BO) {
			if (BO && BO->isAssignmentOp()) {
				if (auto LHS = BO->getLHS()) {
					if (auto DRE = dyn_cast<DeclRefExpr>(LHS->IgnoreParenImpCasts())) {
						if (auto D = DRE->getDecl()) {
							if (auto VD = dyn_cast<VarDecl>(D)) {
								DeclList.insert(VD);
							}
						}
					}
				}
			}
			return true;
		}
	};

	class CheckModifyVarVisitor
		: public RecursiveASTVisitor<CheckModifyVarVisitor> {
		const VarDecl* ModifyVD;
		const Expr* ModifyExpr = nullptr;

	public:
		CheckModifyVarVisitor(const VarDecl* ModifyVD) : ModifyVD(ModifyVD) {}
		const Expr* GetModifyExpr() {
			return ModifyExpr;
		}

	public:
		bool VisitUnaryOperator(const UnaryOperator* UO) {
			if (UO && UO->isIncrementDecrementOp()) {
				if (auto Sub = UO->getSubExpr()) {
					if (auto DRE = dyn_cast<DeclRefExpr>(Sub->IgnoreParenImpCasts())) {
						if (auto D = DRE->getDecl()) {
							if (auto VD = dyn_cast<VarDecl>(D)) {
								if (VD == ModifyVD) {
									ModifyExpr = UO;
									return false;
								}
							}
						}
					}
				}
			}
			return true;
		}

		bool VisitBinaryOperator(const BinaryOperator* BO) {
			if (BO && BO->isAssignmentOp()) {
				if (auto LHS = BO->getLHS()) {
					if (auto DRE = dyn_cast<DeclRefExpr>(LHS->IgnoreParenImpCasts())) {
						if (auto D = DRE->getDecl()) {
							if (auto VD = dyn_cast<VarDecl>(D)) {
								if (VD == ModifyVD) {
									ModifyExpr = BO;
									return false;
								}
							}
						}
					}
				}
			}
			return true;
		}
	};

	class FindVarDeclVisitor
		: public RecursiveASTVisitor<FindVarDeclVisitor> {
		std::set<const VarDecl*> DeclList;

	public:
		const std::set<const VarDecl*>& getDecls() {
			return DeclList;
		}

	public:
		bool VisitDeclRefExpr(const DeclRefExpr* DRE) {
			if (DRE) {
				if (auto D = DRE->getDecl()) {
					if (auto VD = dyn_cast<VarDecl>(D)) {
						DeclList.insert(VD);
					}
				}
			}
			return true;
		}
	};

	class DisableForBodyModifyCtrlVarChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		const VarDecl* findLoopCtrlVar(const ForStmt* FS) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void DisableForBodyModifyCtrlVarChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	const FunctionDecl* FD = dyn_cast<FunctionDecl>(D);
	FindForStmtVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto FS : Stmts) {
		if (auto Body = FS->getBody()) {
			if (auto VD = findLoopCtrlVar(FS)) {
				CheckModifyVarVisitor Check(VD);
				Check.TraverseStmt(const_cast<Stmt*>(Body));
				if (auto ME = Check.GetModifyExpr()) {
					reportBug(FD, ME->getBeginLoc(), BR);
				}
			}
		}
	}
}
const VarDecl* DisableForBodyModifyCtrlVarChecker::findLoopCtrlVar(const ForStmt* FS) const {
	auto Cond = FS->getCond();
	if (!Cond)
		return nullptr;

	if (auto DRE = dyn_cast<DeclRefExpr>(Cond->IgnoreParenCasts())) {
		if (auto D = DRE->getDecl()) {
			if (auto VD = dyn_cast<VarDecl>(D)) {
				return VD;
			}
		}
	}
	else if (auto UO = dyn_cast<UnaryOperator>(Cond->IgnoreParenCasts())) {
		if (UO->getOpcode() == UnaryOperator::Opcode::UO_LNot ||
			UO->getOpcode() == UnaryOperator::Opcode::UO_Deref) {
			if (auto DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr()->IgnoreParenCasts())) {
				if (auto D = DRE->getDecl()) {
					if (auto VD = dyn_cast<VarDecl>(D)) {
						return VD;
					}
				}
			}
		}
	}

	FindVarDeclVisitor ValidVarDeclVisitor;
	ValidVarDeclVisitor.TraverseStmt(const_cast<Expr*>(Cond));
	auto& ValidVarDecls = ValidVarDeclVisitor.getDecls();
	if (!ValidVarDecls.empty()) {
		FindLoopCtrlVarDeclVisitor LoopCtrlVarVisitor;
		if (auto Inc = FS->getInc())
			LoopCtrlVarVisitor.TraverseStmt(const_cast<Expr*>(Inc));
		auto& LoopCtrlVarDecls = LoopCtrlVarVisitor.getDecls();

		if (auto Init = FS->getInit()) {
			if (const DeclStmt* DS = dyn_cast_or_null<DeclStmt>(Init)) {
				for (const Decl* D : DS->decls()) {
					if (const VarDecl* VD = llvm::dyn_cast_or_null<VarDecl>(D)) {
						if (LoopCtrlVarDecls.empty() || LoopCtrlVarDecls.find(VD) != LoopCtrlVarDecls.end()) {
							if (ValidVarDecls.find(VD) != ValidVarDecls.end()) {
								return VD;
							}
						}
					}
				}
			}
			else if (auto E = dyn_cast<Expr>(Init)) {
				if (auto BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts())) {
					if (auto LHS = BO->getLHS()) {
						if (auto DRE = dyn_cast<DeclRefExpr>(LHS->IgnoreParenImpCasts())) {
							if (auto D = DRE->getDecl()) {
								if (auto VD = dyn_cast<VarDecl>(D)) {
									if (ValidVarDecls.find(VD) != ValidVarDecls.end()) {
										return VD;
									}
								}
							}
						}
					}
				}
			}
		}
		else {
			for (auto VD : LoopCtrlVarDecls) {
				if (ValidVarDecls.find(VD) != ValidVarDecls.end()) {
					return VD;
				}
			}
		}
	}

	return nullptr;
}

void DisableForBodyModifyCtrlVarChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "DisableForBodyModifyCtrlVarChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::DisableForBodyModifyCtrlVarChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "DisableForBodyModifyCtrlVarChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDisableForBodyModifyCtrlVarChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<DisableForBodyModifyCtrlVarChecker>();
}

bool ento::shouldRegisterDisableForBodyModifyCtrlVarChecker(const CheckerManager& mgr) {
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
	registry.addChecker<DisableForBodyModifyCtrlVarChecker>("anzu.DisableForBodyModifyCtrlVarChecker", "Modifying the loop control variable inside the body of a for loop is prohibited.", "");
}

#endif