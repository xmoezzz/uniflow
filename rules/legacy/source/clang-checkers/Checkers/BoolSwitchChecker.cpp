#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"


using namespace clang;
using namespace ento;

namespace {
	class FindSwitchStmtVisitor
		: public RecursiveASTVisitor<FindSwitchStmtVisitor> {
		std::list<const SwitchStmt*> StmtList;

	public:
		const std::list<const SwitchStmt*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitSwitchStmt(const SwitchStmt* SS) {
			if (SS) {
				StmtList.push_back(SS);
			}
			return true;
		}
	};

	class BoolSwitchChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void BoolSwitchChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const {
	if (!D)
		return;

	const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);

	if (!FD || !FD->hasBody())
		return;

	FindSwitchStmtVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto SS : Stmts) {
		if (auto Cond = SS->getCond()) {
			if (Cond->IgnoreParenImpCasts()->getType()->isBooleanType()) {
				reportBug(FD, Cond->getBeginLoc(), BR);
			}
		}
	}
}

void BoolSwitchChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "BoolSwitchChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::BoolSwitchChecker, lang);
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(*BT, Msg, createRuleExtData(1, "BoolSwitchChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}


/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBoolSwitchChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BoolSwitchChecker>();
}

bool ento::shouldRegisterBoolSwitchChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BoolSwitchChecker>("anzu.BoolSwitchChecker", "It is prohibited to use a switch statement with a bool variable.", "");
}

#endif