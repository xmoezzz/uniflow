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
	class TaintLoopVariableChecker : public Checker<check::BranchCondition> {
		mutable std::unique_ptr<BugType> BT;

	public:
		TaintLoopVariableChecker() {}

		void checkBranchCondition(const Stmt* Condition, CheckerContext& C) const;
		const Stmt* getCurrentTerminatorStmt(CheckerContext& C) const;
		const Expr* getWhileControlExpr(const Stmt* S) const;
		const Expr* getTaintedWhileControlVar(const Stmt* S, const Expr* E, CheckerContext& C) const;

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
} // end anonymous namespace

void TaintLoopVariableChecker::checkBranchCondition(const Stmt* Condition, CheckerContext& C) const
{
	auto TS = getCurrentTerminatorStmt(C);
	if (!TS)
		return;
	
	auto Cond = getWhileControlExpr(TS);
	if (!Cond)
		return;

	if (auto TaintExpr = getTaintedWhileControlVar(TS, Cond, C)) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::TaintLoopVariableChecker, lang);
		std::string expr = ToString(TaintExpr);
		std::string Msg = std::vformat(fmt, std::make_format_args(expr));
		reportBug(FD, Msg, TaintExpr->getBeginLoc(), C.getBugReporter());
	}
}

const Stmt* TaintLoopVariableChecker::getCurrentTerminatorStmt(CheckerContext& C) const {
	auto ADC = C.getCurrentAnalysisDeclContext();
	if (!ADC)
		return nullptr;

	auto Cfg = ADC->getCFG();
	if (!Cfg)
		return nullptr;

	auto BlockId = C.getBlockID();
	for (auto& Block : *Cfg) {
		if (Block && Block->getBlockID() == BlockId) {
			return Block->getTerminatorStmt();
		}
	}

	return nullptr;
}

const Expr* TaintLoopVariableChecker::getWhileControlExpr(const Stmt* S) const {
	const Expr* Cond = nullptr;
	if (auto FS = dyn_cast<ForStmt>(S)) {
		Cond = FS->getCond();
	}
	if (auto WS = dyn_cast<WhileStmt>(S)) {
		Cond = WS->getCond();
	}
	if (auto DS = dyn_cast<DoStmt>(S)) {
		Cond = DS->getCond();
	}

	return Cond;
}

const Expr* TaintLoopVariableChecker::getTaintedWhileControlVar(const Stmt* S, const Expr* E, CheckerContext& C) const {
	auto BO = dyn_cast<BinaryOperator>(E->IgnoreParenCasts());
	if (!BO)
		return nullptr;

	if (isTaintedOrPointsToTainted(C, BO->getLHS(), TaintTagType::AnyTaint()) && !IsConstantExpr(BO->getRHS()))
		return BO->getLHS();

	if (isTaintedOrPointsToTainted(C, BO->getRHS(), TaintTagType::AnyTaint()) && !IsConstantExpr(BO->getLHS()))
		return BO->getRHS();

	return nullptr;
}

void TaintLoopVariableChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "TaintLoopVariableChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "TaintLoopVariableChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerTaintLoopVariableChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<TaintLoopVariableChecker>();
}

bool ento::shouldRegisterTaintLoopVariableChecker(const CheckerManager& mgr) {
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
	registry.addChecker<TaintLoopVariableChecker>("anzu.TaintLoopVariableChecker", "", "");
}

#endif