#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Stmt.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class CheckEmptyElseBranchChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;
	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
	};
}

class EmptyElseBranchVisitor : public ConstStmtVisitor<EmptyElseBranchVisitor> {
	BugReporter& BR;
	const CheckerBase* Checker;
	BuiltinBug& BT;
	const FunctionDecl* FD = nullptr;

public:
	EmptyElseBranchVisitor(const FunctionDecl* FD, BugReporter& B, const CheckerBase* C, BuiltinBug& BT) : FD(FD), BR(B), Checker(C), BT(BT) {}

	void VisitStmt(const Stmt* S) {
		VisitChildren(S);
	}
	void VisitChildren(const Stmt* S);

	void VisitIfStmt(const IfStmt* IS);
	void ReportEmptyElseBranch(const Stmt* S);
};

void EmptyElseBranchVisitor::VisitChildren(const Stmt* S) {
	for (const Stmt* Child : S->children())
		if (Child)
			Visit(Child);
}

void EmptyElseBranchVisitor::VisitIfStmt(const IfStmt* IS) {
	if (IS->getElse() && IS->getElse()->children().empty())
		ReportEmptyElseBranch(IS->getElse());
}

void EmptyElseBranchVisitor::ReportEmptyElseBranch(const Stmt* S) {
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CheckEmptyElseBranchChecker, lang);
	auto data = ToString(S);
	if (TrimString(data) == ";") {
		PathDiagnosticLocation Loc(S->getBeginLoc(), BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			BT, Msg, createRuleExtData(1, "CheckEmptyElseBranchChecker"), Loc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
}

void CheckEmptyElseBranchChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!BT)
		BT.reset(new BuiltinBug(this, "CheckEmptyElseBranchChecker"));

	if (const Stmt* Body = D->getBody())
		EmptyElseBranchVisitor(dyn_cast<FunctionDecl>(D), BR, this, *BT).Visit(Body);
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCheckEmptyElseBranchChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CheckEmptyElseBranchChecker>();
}

bool ento::shouldRegisterCheckEmptyElseBranchChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CheckEmptyElseBranchChecker>("anzu.CheckEmptyElseBranchChecker", "", "");
}

#endif