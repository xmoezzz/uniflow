#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
    class AssignInSizeofChecker : public Checker<check::PreStmt<UnaryExprOrTypeTraitExpr>>{
        mutable std::unique_ptr<BugType> BT;

    public:
        void checkPreStmt(const UnaryExprOrTypeTraitExpr* UETE, CheckerContext& C) const;

    private:
        void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
    };
}


void AssignInSizeofChecker::checkPreStmt(const UnaryExprOrTypeTraitExpr* UETE, CheckerContext& C) const {
    if (!UETE || UETE->getKind() != UETT_SizeOf)
        return;

    const FunctionDecl* FD = nullptr;
    if (auto ADC = C.getCurrentAnalysisDeclContext()) {
        FD = dyn_cast<FunctionDecl>(ADC->getDecl());
    }

    if (!UETE->isArgumentType()) {
        if (auto Arg = UETE->getArgumentExpr()) {
            if (auto BO = dyn_cast<BinaryOperator>(Arg->IgnoreParenCasts())) {
                if (BO->isAssignmentOp()) {
                    auto ls = anzulocalization::LocaleSetting::getInstance();
		            uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		            std::string Msg = ls->parseMsgs(anzulocalization::AssignInSizeofChecker, lang);  
                    reportBug(FD, Msg, UETE->getOperatorLoc(), C.getBugReporter());
                }
            }
        }
    }
}

void AssignInSizeofChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT)
        BT.reset(new BuiltinBug(this, "AssignInSizeofChecker"));

    // Report the issue        
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "AssignInSizeofChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAssignInSizeofChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<AssignInSizeofChecker>();
}

bool ento::shouldRegisterAssignInSizeofChecker(const CheckerManager& mgr) {
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
    registry.addChecker<AssignInSizeofChecker>("anzu.AssignInSizeofChecker", "It is prohibited to use assignment within sizeof.", "");
}

#endif