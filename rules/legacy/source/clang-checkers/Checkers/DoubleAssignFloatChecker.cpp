#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/CheckerManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
class DoubleAssignFloatChecker : public Checker< check::ASTDecl<VarDecl>, check::PreStmt<BinaryOperator> > {
    mutable std::unique_ptr<BuiltinBug> BT;

public:
    void checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const;
    void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;
    bool isLiteral(const Expr* E) const;
    bool checkExpr(const QualType& LT, const QualType& RT, ASTContext& AST) const;
    void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
};
}

void DoubleAssignFloatChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const {
    if (auto Init = VD->getInit()) {
        if (isLiteral(Init->IgnoreParenCasts()))
            return;

        if (!checkExpr(VD->getType(), Init->IgnoreParenImpCasts()->getType(), mgr.getASTContext()))
            return;

	    auto ls = anzulocalization::LocaleSetting::getInstance();
	    uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	    std::string Msg = ls->parseMsgs(anzulocalization::DisableGotoChecker, lang);

        reportBug(findFunctionDecl(VD), Msg, VD->getBeginLoc(), BR);
    }
}

void DoubleAssignFloatChecker::checkPreStmt(const BinaryOperator *B, CheckerContext &C) const {
    if (B->getOpcode() != BO_Assign)
        return;

    if (isLiteral(B->getRHS()->IgnoreParenCasts()))
        return;

    if (!checkExpr(B->getLHS()->getType(), B->getRHS()->IgnoreParenImpCasts()->getType(), C.getASTContext()))
        return;

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::DoubleAssignFloatChecker, lang);

    const FunctionDecl* FD = nullptr;
    if (auto ADC = C.getCurrentAnalysisDeclContext()) {
        FD = dyn_cast<FunctionDecl>(ADC->getDecl());
    }
    reportBug(FD, Msg, B->getOperatorLoc(), C.getBugReporter());
}

bool DoubleAssignFloatChecker::isLiteral(const Expr* E) const {
    if (!E)
        return false;

    if (isa<CharacterLiteral>(E))
        return true;

    if (isa<IntegerLiteral>(E))
        return true;

    if (isa<FloatingLiteral>(E))
        return true;

    if (isa<FixedPointLiteral>(E))
        return true;

    if (isa<ImaginaryLiteral>(E))
        return true;

    if (isa<StringLiteral>(E))
        return true;

    return false;
}

bool DoubleAssignFloatChecker::checkExpr(const QualType& LT, const QualType& RT, ASTContext& AST) const {
    if (!LT->isFloatingType())
        return false;

    if (!RT->isFloatingType())
        return false;

    return AST.getTypeSize(LT) < AST.getTypeSize(RT);
}

void DoubleAssignFloatChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT)
        BT.reset(new BuiltinBug(this, "DoubleAssignFloatChecker"));

    // Report the issue        
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "DoubleAssignFloatChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDoubleAssignFloatChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<DoubleAssignFloatChecker>();
}

bool ento::shouldRegisterDoubleAssignFloatChecker(const CheckerManager& mgr) {
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
    registry.addChecker<DoubleAssignFloatChecker>("anzu.DoubleAssignFloatChecker", "Double value assigned to float without an explicit cast", "");
}

#endif