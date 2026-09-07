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
class FileHandleCopyChecker : public Checker< check::ASTDecl<VarDecl>, check::PreStmt<BinaryOperator> > {
    mutable std::unique_ptr<BuiltinBug> BT;

public:
    void checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const;
    void checkPreStmt(const BinaryOperator *B, CheckerContext &C) const;
    bool checkExpr(const QualType& LT, const QualType& RT, ASTContext& AST) const;
    void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
};
}

void FileHandleCopyChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const {
    if (auto Init = VD->getInit()) {
        if (IsConstantExpr(Init))
            return;

        if (!checkExpr(VD->getType(), Init->IgnoreParenImpCasts()->getType(), mgr.getASTContext()))
            return;

        reportBug(findFunctionDecl(VD), Init->getBeginLoc(), BR);
    }
}

void FileHandleCopyChecker::checkPreStmt(const BinaryOperator *B, CheckerContext &C) const {
    if (B->getOpcode() != BO_Assign)
        return;

    if (!checkExpr(B->getLHS()->getType(), B->getRHS()->IgnoreParenImpCasts()->getType(), C.getASTContext()))
        return;

    const FunctionDecl* FD = nullptr;
    if (auto ADC = C.getCurrentAnalysisDeclContext()) {
        FD = dyn_cast<FunctionDecl>(ADC->getDecl());
    }

    reportBug(FD, B->getRHS()->getBeginLoc(), C.getBugReporter());
}

bool FileHandleCopyChecker::checkExpr(const QualType& LT, const QualType& RT, ASTContext& AST) const {
    if (LT.getCanonicalType()->isPointerType())
        return false;

    auto strLType = LT.getAsString();
    auto strRType = RT.getAsString();
    return strLType == "FILE";
}

void FileHandleCopyChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT) {
        BT.reset(new BuiltinBug(
            this, "IntegerAssignIntegerChecker"));
    }

    // Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::FileHandleCopyChecker, lang);        
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "FileHandleCopyChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFileHandleCopyChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<FileHandleCopyChecker>();
}

bool ento::shouldRegisterFileHandleCopyChecker(const CheckerManager& mgr) {
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
    registry.addChecker<FileHandleCopyChecker>("anzu.FileHandleCopyChecker", "Do not copy a FILE object", "");
}

#endif