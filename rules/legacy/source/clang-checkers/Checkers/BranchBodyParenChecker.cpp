#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindBranchBodyStmtVisitor
		: public RecursiveASTVisitor<FindBranchBodyStmtVisitor> {
		std::list<const Stmt*> StmtList;

	public:
		const std::list<const Stmt*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitIfStmt(const IfStmt* IS) {
			if (auto Body = IS->getThen()) {
				StmtList.push_back(Body);
			}
			if (auto Body = IS->getElse()) {
				if (auto IE = dyn_cast<IfStmt>(Body); !IE) {
					StmtList.push_back(Body);
				}
			}

			return true;
		}
	};

	class BranchBodyParenChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void BranchBodyParenChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	FindBranchBodyStmtVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto S : Stmts) {
		if (auto CS = dyn_cast<CompoundStmt>(S); !CS) {
			auto Loc = S->getBeginLoc();
			if (!Loc.isMacroID()) {
				reportBug(dyn_cast<FunctionDecl>(D), S->getBeginLoc(), BR);
			}
		}
	}
}

void BranchBodyParenChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "BranchBodyParenChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::BranchBodyParenChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(*BT, Msg, createRuleExtData(1, "BranchBodyParenChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBranchBodyParenChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BranchBodyParenChecker>();
}

bool ento::shouldRegisterBranchBodyParenChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BranchBodyParenChecker>("anzu.BranchBodyParenChecker", "Branch stmt body must use paren", "");
}

#endif