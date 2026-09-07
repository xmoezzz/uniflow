#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindLogicExprVisitor
		: public RecursiveASTVisitor<FindLogicExprVisitor> {
		std::list<const BinaryOperator*> ExprList;

	public:
		const std::list<const BinaryOperator*>& getExprs() {
			return ExprList;
		}

	public:
		explicit FindLogicExprVisitor() {}

		bool VisitBinaryOperator(const BinaryOperator* B) {
			if (B->isLogicalOp()) {
				ExprList.push_back(B);
			}
			return true;
		}
	};

	class AssignmentInLogicalOpChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void AssignmentInLogicalOpChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	FindLogicExprVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	AnalysisDeclContext* AC = Mgr.getAnalysisDeclContext(D);
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::AssignmentInLogicalOpChecker, lang);
	auto Exprs = Visitor.getExprs();
	for (auto B : Exprs) {
		auto LHS = B->getLHS()->IgnoreParenImpCasts();
		auto RHS = B->getRHS()->IgnoreParenImpCasts();
		if ((LHS->getStmtClass() == Stmt::BinaryOperatorClass &&
			cast<BinaryOperator>(LHS)->isAssignmentOp()) ||
			(RHS->getStmtClass() == Stmt::BinaryOperatorClass &&
				cast<BinaryOperator>(RHS)->isAssignmentOp())) {  
			reportBug(D, Msg, B->getOperatorLoc(), BR);
		}
	}
}

void AssignmentInLogicalOpChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "AssignmentInLogicalOpChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "AssignmentInLogicalOpChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAssignmentInLogicalOpChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<AssignmentInLogicalOpChecker>();
}

bool ento::shouldRegisterAssignmentInLogicalOpChecker(const CheckerManager& mgr) {
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
	registry.addChecker<AssignmentInLogicalOpChecker>("anzu.AssignmentInLogicalOpChecker", "Checks for assignment operators used with && or ||", "");
}

#endif