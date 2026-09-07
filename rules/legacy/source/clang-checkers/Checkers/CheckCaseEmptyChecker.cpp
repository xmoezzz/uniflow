#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class CheckCaseEmptyChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
	};
}

class CaseEmptyVisitor : public ConstStmtVisitor<CaseEmptyVisitor> {
	BugReporter& BR;
	const CheckerBase* Checker;
	BuiltinBug& BT;
	const FunctionDecl* FD = nullptr;

public:
	CaseEmptyVisitor(const FunctionDecl* FD, BugReporter& B, const CheckerBase* C, BuiltinBug& BT) : FD(FD), BR(B), Checker(C), BT(BT) {}

	void VisitStmt(const Stmt* S) {
		VisitChildren(S);
	}
	void VisitChildren(const Stmt* S);

	void VisitSwitchStmt(const SwitchStmt* SS);
	void ReportEmptyCase(const Stmt* S);
};

void CaseEmptyVisitor::VisitChildren(const Stmt* S) {
	for (const Stmt* Child : S->children())
		if (Child)
			Visit(Child);
}

void CaseEmptyVisitor::VisitSwitchStmt(const SwitchStmt* SS) {
	const Stmt* PrevCase = nullptr;
	bool CaseHasStatement = false;
	for (const SwitchCase* SC = SS->getSwitchCaseList(); SC; SC = SC->getNextSwitchCase()) {
		if (auto* CS = llvm::dyn_cast_or_null<CaseStmt>(SC)) {
			if (PrevCase && !CaseHasStatement)
				ReportEmptyCase(PrevCase);
			PrevCase = CS;

			CaseHasStatement = true;
			if (auto SCS = CS->getSubStmt()) {
				if (auto NS = dyn_cast<NullStmt>(SCS)) {
					CaseHasStatement = false;
				}
			}
		}
	}

	if (PrevCase && !CaseHasStatement)
		ReportEmptyCase(PrevCase);
}

void CaseEmptyVisitor::ReportEmptyCase(const Stmt* S) {
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CheckCaseEmptyChecker, lang);
	PathDiagnosticLocation Loc(S->getBeginLoc(), BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		BT, Msg, createRuleExtData(1, "CheckCaseEmptyChecker"), Loc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

void CheckCaseEmptyChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	if (Mgr.getASTContext().HasSyntaxErrors()) {
		return;
	}

	if (!BT)
		BT.reset(new BuiltinBug(this, "CheckCaseEmptyChecker"));
	if (const Stmt* Body = D->getBody())
		CaseEmptyVisitor(dyn_cast<FunctionDecl>(D), BR, this, *BT).Visit(Body);
}

// void ento::registerCheckCaseEmptyChecker(CheckerManager &mgr) {
//   mgr.registerChecker<CheckCaseEmptyChecker>();
// }

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCheckCaseEmptyChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CheckCaseEmptyChecker>();
}

bool ento::shouldRegisterCheckCaseEmptyChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CheckCaseEmptyChecker>("anzu.CheckCaseEmptyChecker", "", "");
}

#endif