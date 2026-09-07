#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindBinaryOperatorVisitor
		: public RecursiveASTVisitor<FindBinaryOperatorVisitor> {
		std::list<const BinaryOperator*> ExprList;

	public:
		const std::list<const BinaryOperator*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitBinaryOperator(const BinaryOperator* BO) {
			if (BO && BO->getOpcode() == BO_Assign) {
				ExprList.push_back(BO);
			}
			return true;
		}
	};

	class AssignmentInConditionChecker : public Checker<check::BranchCondition> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkBranchCondition(const Stmt* Condition, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}


void AssignmentInConditionChecker::checkBranchCondition(const Stmt* Condition, CheckerContext& C) const {
	if (!Condition)
		return;

	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}

	FindBinaryOperatorVisitor Visitor;
	Visitor.TraverseStmt(const_cast<Stmt*>(Condition));
	auto Exprs = Visitor.getExprs();
	for (auto BO : Exprs) {
		reportBug(FD, BO->getOperatorLoc(), C.getBugReporter());
	}
}

void AssignmentInConditionChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "AssignmentInConditionChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::AssignmentInConditionChecker, lang);          
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "AssignmentInConditionChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAssignmentInConditionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<AssignmentInConditionChecker>();
}

bool ento::shouldRegisterAssignmentInConditionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<AssignmentInConditionChecker>("anzu.AssignmentInConditionChecker", "Assignment in condition expression", "");
}

#endif