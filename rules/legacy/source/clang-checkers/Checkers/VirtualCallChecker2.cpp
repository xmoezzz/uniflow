#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
    class FindCallVfVisitor
        : public RecursiveASTVisitor<FindCallVfVisitor> {
        const  CXXMemberCallExpr* CallExpr = nullptr;

    public:
		const CXXMemberCallExpr* GetCallExpr() const {
            return CallExpr;
        }

    public:
        bool VisitCXXMemberCallExpr(const CXXMemberCallExpr* MCE) {
            if (auto MD = MCE->getMethodDecl()) {
                if (MD->isVirtual()) {
                    if (auto Obj = MCE->getImplicitObjectArgument()) {
                        if (isa<CXXThisExpr>(Obj->IgnoreParenCasts())) {
							CallExpr = MCE;
                            return false;
                        }
                    }
                }
            }
            return true;
        }
    };

	class VirtualCallChecker2 : public Checker< check::ASTDecl<CXXConstructorDecl>, check::ASTDecl<CXXDestructorDecl>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTDecl(const CXXConstructorDecl* CtorD, AnalysisManager& mgr, BugReporter& BR) const;
		void checkASTDecl(const CXXDestructorDecl* DtorD, AnalysisManager& mgr, BugReporter& BR) const;

		void checkCallVf(const FunctionDecl* FD, AnalysisManager& mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void VirtualCallChecker2::checkASTDecl(const CXXConstructorDecl* CtorD, AnalysisManager& mgr, BugReporter& BR) const {
	if (!CtorD)
		return;

	auto RD = CtorD->getParent();
	if (!RD)
		return;

	//if (!RD->isClass())
	//	return;

	checkCallVf(dyn_cast<FunctionDecl>(CtorD), mgr, BR);
}

void VirtualCallChecker2::checkASTDecl(const CXXDestructorDecl* DtorD, AnalysisManager& mgr, BugReporter& BR) const {
	if (!DtorD)
		return;

	auto RD = DtorD->getParent();
	if (!RD)
		return;

	//if (!RD->isClass())
	//	return;

	checkCallVf(dyn_cast<FunctionDecl>(DtorD), mgr, BR);
}

void VirtualCallChecker2::checkCallVf(const FunctionDecl* FD, AnalysisManager& mgr, BugReporter& BR) const {
	if (!FD)
		return;

	auto Body = FD->getBody();
	if (!Body)
		return;

	FindCallVfVisitor Visitor;
	Visitor.TraverseStmt(const_cast<Stmt*>(Body));
	if (auto MCE = Visitor.GetCallExpr()) {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::VirtualCallChecker2, lang);
		reportBug(FD, Msg, MCE->getBeginLoc(), BR);
	}
}

void VirtualCallChecker2::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "VirtualCallChecker2"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "VirtualCallChecker2"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerVirtualCallChecker2(CheckerManager& Mgr) {
	Mgr.registerChecker<VirtualCallChecker2>();
}

bool ento::shouldRegisterVirtualCallChecker2(const CheckerManager& mgr) {
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
	registry.addChecker<VirtualCallChecker2>("anzu.VirtualCallChecker2", "", "");
}

#endif
