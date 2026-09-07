#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"
#include <unordered_map>

using namespace clang;
using namespace ento;

#define PUSH_STATE() \
bool ExistBreakCache = ExistBreak; \
ExistBreak = false

#define POP_STATE() \
ExistBreak = ExistBreakCache

#define EXIST_BREAK() ExistBreak

#define REPORT_COND(LOOP) \
if (auto Cond = (LOOP)->getCond()) { \
	bool True = false; \
	if (Cond->EvaluateAsBooleanCondition(True, AST) && \
		True) { \
		StmtList.push_back(Cond); \
	} \
} \
else { \
	StmtList.push_back((LOOP)); \
}

namespace {
	class FindInfinityLoopStmtVisitor
		: public RecursiveASTVisitor<FindInfinityLoopStmtVisitor> {
		std::list<const Stmt*> StmtList;
		const ASTContext& AST;
		bool ExistBreak = false;

	public:
		FindInfinityLoopStmtVisitor(const ASTContext& AST) : AST(AST) {}

		const std::list<const Stmt*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitBreakStmt(const BreakStmt* BS) {
			ExistBreak = true;
			return true;
		}

		bool TraverseWhileStmt(WhileStmt* WS) {
			PUSH_STATE();
			auto r = RecursiveASTVisitor<FindInfinityLoopStmtVisitor>::TraverseWhileStmt(WS);

			if (!EXIST_BREAK()) {
				REPORT_COND(WS);
			}

			POP_STATE();

			return r;
		}

		bool TraverseForStmt(ForStmt* FS) {
			PUSH_STATE();
			auto r = RecursiveASTVisitor<FindInfinityLoopStmtVisitor>::TraverseForStmt(FS);

			if (!EXIST_BREAK()) {
				REPORT_COND(FS);
			}

			POP_STATE();
			return r;
		}

		bool TraverseDoStmt(DoStmt* DS) {
			PUSH_STATE();
			auto r = RecursiveASTVisitor<FindInfinityLoopStmtVisitor>::TraverseDoStmt(DS);

			if (!EXIST_BREAK()) {
				REPORT_COND(DS);
			}

			POP_STATE();
			return r;
		}

		bool TraverseSwitchStmt(SwitchStmt* DS) {
			return true;
		}
	};

	class InfinityLoopChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void InfinityLoopChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	auto FD = dyn_cast<FunctionDecl>(D);
	FindInfinityLoopStmtVisitor Visitor(Mgr.getASTContext());
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto S : Stmts) {
		reportBug(FD, S->getBeginLoc(), BR);
	}
}

void InfinityLoopChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;

	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "InfinityLoopChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::InfinityLoopChecker, lang);       
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "InfinityLoopChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerInfinityLoopChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<InfinityLoopChecker>();
}

bool ento::shouldRegisterInfinityLoopChecker(const CheckerManager& mgr) {
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
	registry.addChecker<InfinityLoopChecker>("anzu.InfinityLoopChecker", "Use infinite loop statements with caution.", "");
}

#endif