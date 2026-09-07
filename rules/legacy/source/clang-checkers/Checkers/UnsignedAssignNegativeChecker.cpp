#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

    class UnsignedTypeAssignNegativeChecker : public Checker<check::PreStmt<BinaryOperator>> {
        mutable std::unique_ptr<BuiltinBug> BT;
    public:
        void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
        void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
    };

} // end anonymous namespace

void UnsignedTypeAssignNegativeChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
    if (B->getOpcode() != BO_Assign) {
        return;
    }

    const Expr* RHS = B->getRHS();
    const Expr* LHS = B->getLHS();

    QualType LHSType = LHS->getType();
    if (!LHSType->isUnsignedIntegerType()) {
        return;
    }

    QualType RealRHSType = RHS->IgnoreImpCasts()->getType();
    if (!RealRHSType->isSignedIntegerType()) {
        return;
    }

    SVal RHSVal = C.getSVal(RHS);
    SVal RealRHSVal = C.getSValBuilder().evalCast(RHSVal, RealRHSType, RHSVal.getType(C.getASTContext()));
    auto RHSNonLoc = RealRHSVal.getAs<NonLoc>();
    if (!RHSNonLoc)
        return;

    // 使用约束管理器获取有关符号的信息
    ConstraintManager& CM = C.getConstraintManager();

    // 创建一个用于比较的0值
    const auto Zero = C.getSValBuilder().makeZeroVal(RealRHSType).castAs<NonLoc>();

    ProgramStateRef State = C.getState();
    auto Cond = C.getSValBuilder().evalBinOpNN(State, BO_LT, *RHSNonLoc, Zero, C.getSValBuilder().getConditionType()).getAs<DefinedSVal>();
    if (!Cond) {
        return;
    }
    // 检查符号值是否小于0
    auto IsNegative = CM.assume(State, *Cond, true);
    if (IsNegative) {
        const FunctionDecl* FD = nullptr;
        if (auto ADC = C.getCurrentAnalysisDeclContext()) {
            FD = dyn_cast<FunctionDecl>(ADC->getDecl());
        }

        reportBug(FD, B->getOperatorLoc(), C.getBugReporter());
    }
}

void UnsignedTypeAssignNegativeChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT)
        BT.reset(new BuiltinBug(this, "UnsignedTypeAssignNegativeChecker"));

    // Report the issue            
    auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::UnsignedTypeAssignNegativeChecker, lang);
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "UnsignedTypeAssignNegativeChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUnsignedTypeAssignNegativeChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<UnsignedTypeAssignNegativeChecker>();
}

bool ento::shouldRegisterUnsignedTypeAssignNegativeChecker(const CheckerManager& mgr) {
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
    registry.addChecker<UnsignedTypeAssignNegativeChecker>("anzu.UnsignedTypeAssignNegativeChecker", "Prohibit assigning negative values to unsigned type variables", "");
}

#endif