#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindSwitchStmtVisitor
		: public RecursiveASTVisitor<FindSwitchStmtVisitor> {
		std::list<const Stmt*> StmtList;

	public:
		const std::list<const Stmt*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitSwitchStmt(const SwitchStmt* SS) {
			StmtList.push_back(SS->getBody());
			return true;
		}
	};

	class EmptySwitchChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void EmptySwitchChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	if (Mgr.getASTContext().HasSyntaxErrors()) {
		return;
	}

	auto FD = dyn_cast<FunctionDecl>(D);
	FindSwitchStmtVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto S : Stmts) {
		if (!S) {
			reportBug(FD, S->getBeginLoc(), BR);
		}
		else if (auto NS = dyn_cast<NullStmt>(S)) {
			reportBug(FD, S->getBeginLoc(), BR);
		}
		else if (auto CS = dyn_cast<CompoundStmt>(S)) {
			if (CS->children().empty()) {
				reportBug(FD, S->getBeginLoc(), BR);
			}
		}
	}
}

void EmptySwitchChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "EmptySwitchChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::EmptySwitchChecker, lang);       
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "EmptySwitchChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerEmptySwitchChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<EmptySwitchChecker>();
}

bool ento::shouldRegisterEmptySwitchChecker(const CheckerManager& mgr) {
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
	registry.addChecker<EmptySwitchChecker>("anzu.EmptySwitchChecker", "Empty switch statements are prohibited.", "");
}

#endif