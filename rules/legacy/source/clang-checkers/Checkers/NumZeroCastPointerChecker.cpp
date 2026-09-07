#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FindNullExprVisitor
		: public RecursiveASTVisitor<FindNullExprVisitor> {
		ASTContext& AST;
		std::list<const IntegerLiteral*> StmtList;

	public:
		FindNullExprVisitor(ASTContext& AST) :AST(AST) {}
		const std::list<const IntegerLiteral*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitImplicitCastExpr(const ImplicitCastExpr* ICE) {
			if (ICE) {
				if (ICE->getType()->isPointerType()) {
					if (auto Sub = ICE->getSubExpr()) {
						if (auto IL = dyn_cast<IntegerLiteral>(Sub->IgnoreParens())) {
							if (IL->getValue() == 0) {
								if (!IL->getBeginLoc().isMacroID()) {
									StmtList.push_back(IL);
								}
							}
						}
					}
				}
			}
			return true;
		}
	};

	class NumZeroCastPointerChecker : public Checker<check::ASTDecl<VarDecl>, check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr,
			BugReporter& BR) const;
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
	private:
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void NumZeroCastPointerChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr,
	BugReporter& BR) const {

	auto FD = findFunctionDecl(VD);
	if (FD)
		return;

	if (auto Init = VD->getInit()) {
		FindNullExprVisitor Visitor(Mgr.getASTContext());
		Visitor.TraverseStmt(const_cast<Expr*>(Init));
		auto Stmts = Visitor.getStmts();
		for (auto IL : Stmts) {
			reportBug(FD, IL->getBeginLoc(), BR);
		}
	}
}

void NumZeroCastPointerChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	const FunctionDecl* FD = dyn_cast<FunctionDecl>(D);
	FindNullExprVisitor Visitor(Mgr.getASTContext());
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto IL : Stmts) {
		reportBug(FD, IL->getBeginLoc(), BR);
	}
}

void NumZeroCastPointerChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(this, "NumZeroCastPointerChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::NumZeroCastPointerChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "NumZeroCastPointerChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerNumZeroCastPointerChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<NumZeroCastPointerChecker>();
}

bool ento::shouldRegisterNumZeroCastPointerChecker(const CheckerManager& mgr) {
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
	registry.addChecker<NumZeroCastPointerChecker>("anzu.NumZeroCastPointerChecker", "Prohibits the use of 0 as pointer", "");
}

#endif