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
class CheckEmptyBranchChecker : public Checker<check::ASTCodeBody> {
  mutable std::unique_ptr<BuiltinBug> BT;

public:
  void checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const;
};

class EmptyBranchVisitor : public ConstStmtVisitor<EmptyBranchVisitor> {
    const FunctionDecl* FD;
    AnalysisDeclContext* DCtx;
    BugReporter& BR;
    const CheckerBase* Checker;

public:
    EmptyBranchVisitor(const FunctionDecl* FD, AnalysisDeclContext* ADCtx, BugReporter& B, const CheckerBase* C) : FD(FD), DCtx(ADCtx), BR(B), Checker(C) {}

    void VisitStmt(const Stmt* S) {
        VisitChildren(S);
    }
    void VisitChildren(const Stmt* S);

    void VisitIfStmt(const IfStmt* IS);
    void ReportEmptyBranch(const Stmt* S);
};

void EmptyBranchVisitor::VisitChildren(const Stmt* S) {
    for (const Stmt* Child : S->children())
        if (Child)
            Visit(Child);
}

void EmptyBranchVisitor::VisitIfStmt(const IfStmt* IS) {
    if (IS->getThen() && IS->getThen()->children().empty())
        ReportEmptyBranch(IS->getThen());
    if (IS->getElse() && IS->getElse()->children().empty())
        ReportEmptyBranch(IS->getElse());
}

void EmptyBranchVisitor::ReportEmptyBranch(const Stmt* S) {
    if (S->getBeginLoc().isMacroID())
        return;
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CheckEmptyBranchChecker, lang);

    auto data = ToString(S);
    if (TrimString(data) == ";") {
        BR.EmitBasicReport(FD, Checker, "CheckEmptyBranchChecker",
            "", Msg, createRuleExtData(1, "CheckEmptyBranchChecker"),
            PathDiagnosticLocation(S, BR.getSourceManager(), DCtx));
    }
}

}

void CheckEmptyBranchChecker::checkASTCodeBody(const Decl *D, AnalysisManager &Mgr, BugReporter &BR) const {
  if (const Stmt *Body = D->getBody())
    EmptyBranchVisitor(dyn_cast<FunctionDecl>(D), Mgr.getAnalysisDeclContext(D), BR, this).Visit(Body);
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCheckEmptyBranchChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<CheckEmptyBranchChecker>();
}

bool ento::shouldRegisterCheckEmptyBranchChecker(const CheckerManager& mgr) {
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
    registry.addChecker<CheckEmptyBranchChecker>("anzu1.CheckEmptyBranchChecker", "", "");
}

#endif