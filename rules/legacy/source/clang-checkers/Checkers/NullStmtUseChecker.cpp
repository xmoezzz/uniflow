#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <list>
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
    class FindNullStmtVisitor
        : public RecursiveASTVisitor<FindNullStmtVisitor> {
        std::list<const NullStmt*> StmtList;

    public:
        const std::list<const NullStmt*>& getStmts() {
            return StmtList;
        }

    public:
        bool VisitNullStmt(const NullStmt* UO) {
            StmtList.push_back(UO);
            return true;
        }

        bool TraverseForStmt(ForStmt* FS) {
            if (auto Body = FS->getBody()) {
                if (!isa<NullStmt>(Body)) {
                    TraverseStmt(Body);
                }
            }

            return true;
        }

        bool TraverseWhileStmt(WhileStmt* WS) {
            if (auto Body = WS->getBody()) {
                if (!isa<NullStmt>(Body)) {
                    TraverseStmt(Body);
                }
            }

            return true;
        }

        bool TraverseDoStmt(DoStmt* DS) {
            if (auto Body = DS->getBody()) {
                if (!isa<NullStmt>(Body)) {
                    TraverseStmt(Body);
                }
            }

            return true;
        }

        bool TraverseIfStmt(IfStmt* IS) {
            if (auto Then = IS->getThen()) {
                if (!isa<NullStmt>(Then)) {
                    TraverseStmt(Then);
                }
            }
            if (auto Else = IS->getElse()) {
                if (!isa<NullStmt>(Else)) {
                    TraverseStmt(Else);
                }
            }

            return true;
        }
    };

    class NullStmtUseChecker : public Checker<check::ASTCodeBody> {
        mutable std::unique_ptr<BuiltinBug> BT;

    public:
        void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
            BugReporter& BR) const;

        void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
    };

    void NullStmtUseChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
        BugReporter& BR) const
    {
        if (Mgr.getASTContext().HasSyntaxErrors()) {
            return;
        }
        auto FD = dyn_cast<FunctionDecl>(D);
        FindNullStmtVisitor Visitor;
        Visitor.TraverseDecl(const_cast<Decl*>(D));
        auto Stmts = Visitor.getStmts();
        for (auto NS : Stmts) {
            auto Loc = NS->getSemiLoc();
            if (!Loc.isMacroID()) {
                reportBug(FD, NS->getSemiLoc(), BR);
            }
        }
    }

    void NullStmtUseChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
        if (Loc.isMacroID())
            return;

        if (Loc.isInvalid())
            return;

        if (!BT) {
            BT.reset(new BuiltinBug(
                this, "NullStmtUseChecker"));
        }

        // Report the issue
        auto ls = anzulocalization::LocaleSetting::getInstance();
        uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
        std::string Msg = ls->parseMsgs(anzulocalization::NullStmtUseChecker, lang);        
        PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
        auto Report = std::make_unique<BasicBugReport>(
            *BT, Msg, createRuleExtData(1, "NullStmtUseChecker"), DLoc);
        Report->setDeclWithIssue(FD);
        BR.emitReport(std::move(Report));
    }

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerNullStmtUseChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<NullStmtUseChecker>();
}

bool ento::shouldRegisterNullStmtUseChecker(const CheckerManager& mgr) {
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
    registry.addChecker<NullStmtUseChecker>("anzu.NullStmtUseChecker", "Avoid using empty statements.", "");
}

#endif