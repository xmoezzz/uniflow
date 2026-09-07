#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"
#include <unordered_map>
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {
    enum VD_STATUS {
        VD_STATUS_GET = 1 << 0,
        VD_STATUS_SET = 1 << 1,
    };

    class InvalidExprVisitor
        : public RecursiveASTVisitor<InvalidExprVisitor> {
        std::list<const Expr*> ExprList;
        std::unordered_map<const ValueDecl*, VD_STATUS> DS;
        std::unordered_set<const Stmt*> SS;

    public:
        const std::list<const Expr*>& getExprs() {
            return ExprList;
        }

    public:
        bool VisitStmt(const Stmt* IS) {
            if (!isa<ValueStmt>(IS) || SS.find(IS) != SS.end()) {
                DS.clear();
            }
            return true;
        }

        bool VisitCompoundStmt(CompoundStmt* CS) {
            for (auto Child : CS->children()) {
                if (Child) {
                    SS.insert(Child);
                }
            }

            return true;
        }

        bool VisitIfStmt(IfStmt* IS) {
            if (auto DS = IS->getConditionVariableDeclStmt()) {
                SS.insert(DS);
            }
            if (auto Cond = IS->getCond()) {
                SS.insert(Cond);
            }

            if (auto Then = IS->getThen()) {
                SS.insert(Then);
            }

            if (auto Else = IS->getElse()) {
                SS.insert(Else);
            }

            return true;
        }

        bool VisitDoStmt(DoStmt* DS) {
            if (auto Cond = DS->getCond()) {
                SS.insert(Cond);
            }
            if (auto Body = DS->getBody()) {
                SS.insert(Body);
            }

            return true;
        }

        bool VisitWhileStmt(WhileStmt* WS) {
            if (auto Cond = WS->getCond()) {
                SS.insert(Cond);
            }
            if (auto Body = WS->getBody()) {
                SS.insert(Body);
            }

            return true;
        }

        bool VisitForStmt(ForStmt* FS) {
            if (auto Init = FS->getInit()) {
                SS.insert(Init);
            }
            if (auto Cond = FS->getCond()) {
                SS.insert(Cond);
            }
            if (auto Inc = FS->getInc()) {
                SS.insert(Inc);
            }

            if (auto Body = FS->getBody()) {
                SS.insert(Body);
            }

            return true;
        }

        bool VisitUnaryOperator(const UnaryOperator* UO) {
            if (UO->isIncrementDecrementOp()) {
                if (auto SE = UO->getSubExpr()) {
                    if (auto DRE = dyn_cast<DeclRefExpr>(SE)) {
                        if (auto D = DRE->getDecl()) {
                            auto it = DS.find(D);
                            if (it == DS.end()) {
                                DS[D] = VD_STATUS_SET;
                            }
                            else if (it->second & (VD_STATUS_GET | VD_STATUS_SET)) {
                                it->second = (VD_STATUS)(it->second | VD_STATUS_SET);
                                ExprList.push_back(DRE);
                            }
                        }
                    }
                }
            }
            return true;
        }

        bool VisitBinaryOperator(const BinaryOperator* BO) {
            if (BO->isLogicalOp()) {
                DS.clear();
            }
            else if (BO->isCommaOp()) {
                DS.clear();
            }
            else {
                HandleReclRefExpr(BO->getLHS());
                HandleReclRefExpr(BO->getRHS());
            }
            return true;
        }

        bool VisitCallExpr(const CallExpr* CE) {
            for (int i = 0; i < CE->getNumArgs(); ++i) {
                if (auto Arg = CE->getArg(i)) {
                    HandleReclRefExpr(Arg);
                }
            }
            return true;
        }

        void HandleReclRefExpr(const Expr* E) {
            if (E) {
                if (auto DRE = dyn_cast<DeclRefExpr>(E->IgnoreImpCasts())) {
                    if (auto D = DRE->getDecl()) {
                        auto it = DS.find(D);
                        if (it == DS.end()) {
                            DS[D] = VD_STATUS_GET;
                        }
                        else if (it->second & VD_STATUS_SET) {
                            it->second = (VD_STATUS)(it->second | VD_STATUS_GET);
                            ExprList.push_back(DRE);
                        }
                    }
                }
            }
        }
    };
    class ValueDependSequencePointChecker : public Checker<check::ASTCodeBody> {
        mutable std::unique_ptr<BugType> BT;

    public:
        void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
            BugReporter& BR) const;

    private:
        void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
    };
}


void ValueDependSequencePointChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
    BugReporter& BR) const
{
    InvalidExprVisitor Visitor;
    Visitor.TraverseDecl(const_cast<Decl*>(D));
    auto Exprs = Visitor.getExprs();
    for (auto E : Exprs) {
        reportBug(D, E->getBeginLoc(), BR);
    }
}

void ValueDependSequencePointChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT) {
        BT.reset(new BuiltinBug(
            this, "ValueDependSequencePointChecker"));
    }

    // Report the issue        
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::ValueDependSequencePointChecker, lang);    
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "ValueDependSequencePointChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerValueDependSequencePointChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<ValueDependSequencePointChecker>();
}

bool ento::shouldRegisterValueDependSequencePointChecker(const CheckerManager& mgr) {
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
    registry.addChecker<ValueDependSequencePointChecker>("anzu1.ValueDependSequencePointChecker", "Do not rely on the evaluation order between sequence points", "");
}

#endif