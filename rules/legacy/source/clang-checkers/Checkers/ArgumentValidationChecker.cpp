#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

class ArgumentValidationChecker : public Checker<check::PreCall> {
    mutable std::unique_ptr<BuiltinBug> BT;

public:
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
    void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
};

void ArgumentValidationChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
    if (C.getASTContext().HasSyntaxErrors()) {
        return;
    }

	if (!Call.getDecl())
		return;
    const auto *FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());

    if (!FD)
        return;

    auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::ArgumentValidationChecker, lang);
    for (unsigned i = 0; i < Call.getNumArgs() && i < FD->getNumParams(); ++i) {
        const auto *ArgExpr = Call.getArgExpr(i);
        const ParmVarDecl* PVD = FD->getParamDecl(i);
        if (!ArgExpr || !ArgExpr->getType()->isPointerType() || !PVD)
            continue;

        SVal ArgVal = Call.getArgSVal(i);
        if (C.getState()->isNull(ArgVal).isConstrainedTrue()) {
            std::string pvd = PVD->getNameAsString();
		    std::string Msg = std::vformat(fmt, std::make_format_args(pvd));

            const FunctionDecl* FD = nullptr;
            if (auto ADC = C.getCurrentAnalysisDeclContext()) {
                FD = dyn_cast<FunctionDecl>(ADC->getDecl());
            }
            reportBug(FD, Msg, ArgExpr->getExprLoc(), C.getBugReporter());
        }
    }
}

void ArgumentValidationChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT)
        BT.reset(new BuiltinBug(this, "ArgumentValidationChecker"));

    // Report the issue        
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "ArgumentValidationChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerArgumentValidationChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<ArgumentValidationChecker>();
}

bool ento::shouldRegisterArgumentValidationChecker(const CheckerManager& mgr) {
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
    registry.addChecker<ArgumentValidationChecker>("anzu.ArgumentValidationChecker", "", "");
}

#endif