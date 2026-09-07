#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/Stmt.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindForInfinityCondVisitor
		: public RecursiveASTVisitor<FindForInfinityCondVisitor> {
		ASTContext& AST;
		std::list<const BinaryOperator*> ExprList;

	public:
		FindForInfinityCondVisitor(ASTContext& AST) : AST(AST) {}
		const std::list<const BinaryOperator*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitForStmt(const ForStmt* FS) {
			if (auto BO = dyn_cast<BinaryOperator>(FS->getCond()->IgnoreParenCasts())) {
				if (BO->getOpcode() == BinaryOperatorKind::BO_EQ ||
					BO->getOpcode() == BinaryOperatorKind::BO_NE) {
					if (auto DRE = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenCasts())) {
						if (IsIncGreaterThanOne(DRE->getDecl(), FS->getInc())) {
							ExprList.push_back(BO);
						}
					}
					if (auto DRE = dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreParenCasts())) {
						if (IsIncGreaterThanOne(DRE->getDecl(), FS->getInc())) {
							ExprList.push_back(BO);
						}
					}
				}
			}
			return true;
		}

		bool IsIncGreaterThanOne(const Decl* VD, const Expr* Inc, bool CheckSelfAssign = true) {
			if (!VD || !Inc)
				return false;

			if (auto BO = dyn_cast<BinaryOperator>(Inc->IgnoreParenCasts())) {
				if (!CheckSelfAssign && (BO->getOpcode() == BinaryOperatorKind::BO_Add ||
					BO->getOpcode() == BinaryOperatorKind::BO_Sub) ||
					CheckSelfAssign && (BO->getOpcode() == BinaryOperatorKind::BO_AddAssign ||
						BO->getOpcode() == BinaryOperatorKind::BO_SubAssign)) {
					auto DRE = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenCasts());
					if (!DRE)
						return false;

					if (DRE->getDecl() != VD) {
						return false;
					}

					Expr::EvalResult Result;
					if (BO->getRHS()->EvaluateAsInt(Result, AST)) {
						auto Value = Result.Val.getInt();
						if (Value >= 2 || Value <= -2) {
							return true;
						}
					}
				}

				if (BO->getOpcode() == BinaryOperatorKind::BO_Assign) {
					auto DRE = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenCasts());
					if (!DRE)
						return false;

					if (DRE->getDecl() != VD) {
						return false;
					}

					return IsIncGreaterThanOne(VD, BO->getRHS(), false);
				}
			}

			return false;
		}
	};

	class LoopInequalityChecker : public Checker<check::ASTCodeBody> {
	public:
		mutable std::unique_ptr<BuiltinBug> BT;

		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void LoopInequalityChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
		FindForInfinityCondVisitor Visitor(Mgr.getASTContext());
		Visitor.TraverseDecl(const_cast<Decl*>(D));
		auto Exprs = Visitor.getExprs();
		for (auto BO : Exprs) {
			reportBug(D, BO->getOperatorLoc(), BR);
		}
	}

	void LoopInequalityChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "LoopInequalityChecker"));

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::LoopInequalityChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "LoopInequalityChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerLoopInequalityChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<LoopInequalityChecker>();
}

bool ento::shouldRegisterLoopInequalityChecker(const CheckerManager& mgr) {
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
	registry.addChecker<LoopInequalityChecker>("anzu.LoopInequalityChecker", "", "");
}

#endif
