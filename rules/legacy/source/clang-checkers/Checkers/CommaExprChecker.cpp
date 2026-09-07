#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
    class FindCommaExprVisitor
        : public RecursiveASTVisitor<FindCommaExprVisitor> {
        std::list<const Expr*> ExprList;

    public:
        const std::list<const Expr*>& getExprs() {
            return ExprList;
        }

    public:
        bool VisitBinaryOperator(BinaryOperator* BO) {
            if (BO->getOpcode() == BO_Comma) {
                ExprList.push_back(BO);
            }

            return true;
        }

        bool TraverseDeclStmt(DeclStmt* IS) {
            return true;
        }

        bool TraverseForStmt(ForStmt* FS) {
            if (auto Cond = FS->getCond()) {
                TraverseStmt(Cond);
            }

            if (auto Body = FS->getBody()) {
                TraverseStmt(Body);
            }

            return true;
        }
    };

    class CommaExprChecker : public Checker<check::ASTCodeBody> {
        mutable std::unique_ptr<BugType> BT;

    public:
        void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
            BugReporter& BR) const;

    private:
        void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
    };
}


void CommaExprChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
    BugReporter& BR) const
{
    FindCommaExprVisitor Visitor;
    Visitor.TraverseDecl(const_cast<Decl*>(D));
    auto Exprs = Visitor.getExprs();
    for (auto E : Exprs) {
        auto Loc = E->getBeginLoc();
        if (!Loc.isMacroID()) {
            reportBug(dyn_cast<FunctionDecl>(D), E->getBeginLoc(), BR);
        }
    }
}

void CommaExprChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
    if (!BT) {
        BT.reset(new BuiltinBug(
            this, "CommaExprChecker"));
            }

    // Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CommaExprChecker, lang);              
    PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
    auto Report = std::make_unique<BasicBugReport>(
        *BT, Msg, createRuleExtData(1, "CommaExprChecker"), DLoc);
    Report->setDeclWithIssue(FD);
    BR.emitReport(std::move(Report));
}


/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCommaExprChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CommaExprChecker>();
}

bool ento::shouldRegisterCommaExprChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CommaExprChecker>("anzu.CommaExprChecker", "Avoid using the comma operator.", "");
}

#endif