#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindGotoStmtVisitor
		: public RecursiveASTVisitor<FindGotoStmtVisitor> {
		std::list<const Stmt*> StmtList;

	public:
		const std::list<const Stmt*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitGotoStmt(const GotoStmt* GS) {			
			StmtList.push_back(GS);
			return true;
		}
	};

	class DisableGotoChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void DisableGotoChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	FindGotoStmtVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto S : Stmts) {
		reportBug(dyn_cast<FunctionDecl>(D), S->getBeginLoc(), BR);
	}
}

void DisableGotoChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "DisableGotoChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::DisableGotoChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "DisableGotoChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDisableGotoChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<DisableGotoChecker>();
}

bool ento::shouldRegisterDisableGotoChecker(const CheckerManager& mgr) {
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
	registry.addChecker<DisableGotoChecker>("anzu.DisableGotoChecker", "The use of goto statements is prohibited.", "");
}

#endif