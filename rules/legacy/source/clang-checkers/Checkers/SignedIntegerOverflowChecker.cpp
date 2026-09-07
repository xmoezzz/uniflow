#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/CheckerManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"
#include <unordered_map>

using namespace clang;
using namespace ento;

namespace {
    class FindBinaryOperatorVisitor
        : public RecursiveASTVisitor<FindBinaryOperatorVisitor> {
        ASTContext& AST;
        std::unordered_map<const BinaryOperator*, llvm::APSInt>& CheckExprs;
    public:
        FindBinaryOperatorVisitor(ASTContext& AST, std::unordered_map<const BinaryOperator*, llvm::APSInt>& CheckExprs) 
            : AST(AST), CheckExprs(CheckExprs){}

    public:
        bool VisitVarDecl(const VarDecl* VD) {
            if (!VD)
                return true;

            auto Init = VD->getInit();
            if (!Init)
                return true;

            auto LT = VD->getType();
            Init = Init->IgnoreParenImpCasts();

            if (!LT->isIntegralOrEnumerationType())
                return true;

            if (!Init->getType()->isIntegralOrEnumerationType())
                return true;

            (void)add(LT, Init);
            return true;
        }

        bool VisitBinaryOperator(const BinaryOperator* BO) {
            if (!BO)
                return true;

            if (BO->getOpcode() != BO_Assign)
                return true;

            auto LT = BO->getLHS()->getType();
            auto Init = BO->getRHS()->IgnoreParenImpCasts();

            if (!LT->isIntegralOrEnumerationType())
                return true;

            if (!Init->getType()->isIntegralOrEnumerationType())
                return true;

            (void)add(LT, Init);
            return true;
        }

        bool add(const QualType& QT, const Expr* E) const {
            if (!E)
                return false;

            if (auto BO = dyn_cast<BinaryOperator>(E->IgnoreParenCasts())) {
                if (BO->isAdditiveOp()) {
                    auto T = BO->getLHS()->getType();
                    if (T->isSignedIntegerOrEnumerationType()) {
                        llvm::APSInt MaxValue;
                        if (QT->isSignedIntegerType()) {
                            MaxValue = llvm::APSInt::getMaxValue(AST.getTypeSize(QT), false);
                        }
                        else {
                            MaxValue = llvm::APSInt::getMaxValue(AST.getTypeSize(QT), true);
                        }

                        CheckExprs[BO] = MaxValue;
                        return true;
                    }
                }
            }

            return false;
        }
    };

    class SignedIntegerOverflowChecker : public Checker< check::ASTCodeBody, check::PostStmt<BinaryOperator> > {
        mutable std::unique_ptr<BuiltinBug> BT;
        mutable std::unordered_map<const BinaryOperator*, llvm::APSInt> CheckExprs;

    public:
        void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
        void checkPostStmt(const BinaryOperator* BO, CheckerContext& C) const;
        bool checkOverflow(const BinaryOperator* BO, CheckerContext& C) const;
        void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
    };
}

void SignedIntegerOverflowChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
    BugReporter& BR) const
{
    FindBinaryOperatorVisitor Visitor(Mgr.getASTContext(), CheckExprs);
    Visitor.TraverseDecl(const_cast<Decl*>(D));
}

void SignedIntegerOverflowChecker::checkPostStmt(const BinaryOperator* BO, CheckerContext& C) const {
    if (!checkOverflow(BO, C))
        return;

    const FunctionDecl* FD = nullptr;
    if (auto ADC = C.getCurrentAnalysisDeclContext()) {
        FD = dyn_cast<FunctionDecl>(ADC->getDecl());
    }

    reportBug(FD, BO->getOperatorLoc(), C.getBugReporter());
}

bool SignedIntegerOverflowChecker::checkOverflow(const BinaryOperator* BO, CheckerContext& C) const {
    if (!BO->isAdditiveOp())
        return false;

    auto it = CheckExprs.find(BO);
    if (it == CheckExprs.end())
        return false;

    auto MaxVal = C.getSValBuilder().makeIntVal(it->second);
    auto CurVal = C.getSVal(BO);
    CheckExprs.erase(it);

    auto CondVal = C.getSValBuilder().evalBinOp(C.getState(), BinaryOperator::Opcode::BO_GE, MaxVal, CurVal, C.getSValBuilder().getConditionType());
    if (!isa<DefinedSVal>(CondVal)) {
        return false;
    }

    ProgramStateRef StateTrue, StateFalse;
    std::tie(StateTrue, StateFalse) = C.getState()->assume(CondVal.castAs<DefinedSVal>());

    if (!StateTrue && StateFalse)
        return true;

    return false;
}

void SignedIntegerOverflowChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT)
        BT.reset(new BuiltinBug(this, "SignedIntegerOverflowChecker"));

    // Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::SignedIntegerOverflowChecker, lang);        
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "SignedIntegerOverflowChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSignedIntegerOverflowChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<SignedIntegerOverflowChecker>();
}

bool ento::shouldRegisterSignedIntegerOverflowChecker(const CheckerManager& mgr) {
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
    registry.addChecker<SignedIntegerOverflowChecker>("anzu.SignedIntegerOverflowChecker", "Signed integer overflow", "");
}

#endif