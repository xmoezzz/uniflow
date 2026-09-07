#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FindConditionExprVisitor
		: public RecursiveASTVisitor<FindConditionExprVisitor> {
		std::list<const IfStmt*> StmtList;

	public:
		const std::list<const IfStmt*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitIfStmt(const IfStmt* IS) {
			if (IS) {
				StmtList.push_back(IS);
			}
			return true;
		}
	};

	class EmptyBranchChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void EmptyBranchChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const {
	if (!D)
		return;

	auto& Ctx = BR.getContext();
	auto& SM = BR.getSourceManager();
	const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);

	if (!FD || !FD->hasBody())
		return;

	FindConditionExprVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto IS : Stmts) {
		if (auto Then = IS->getThen()) {
			if (auto NS = dyn_cast<NullStmt>(Then)) {
				SourceLocation Loc1 = NS->getSemiLoc();
				int num1 = SM.getSpellingLineNumber(Loc1);

				SourceLocation Loc2 = IS->getIfLoc();
				int num2 = SM.getSpellingLineNumber(Loc2);

				if (num1 == num2) {
					reportBug(FD, Loc1, BR);
				}
			}
		}
	}
}


void EmptyBranchChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "EmptyBranchChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::EmptyBranchChecker, lang);
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "EmptyBranchChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerEmptyBranchChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<EmptyBranchChecker>();
}

bool ento::shouldRegisterEmptyBranchChecker(const CheckerManager& mgr) {
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
	registry.addChecker<EmptyBranchChecker>("anzu.EmptyBranchChecker", "If a conditional branch is empty, it must be explicitly documented on a separate line with a semicolon and a comment.", "");
}

#endif