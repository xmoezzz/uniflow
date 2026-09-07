#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FindNotExprVisitor
		: public RecursiveASTVisitor<FindNotExprVisitor> {
		std::list<const UnaryOperator*> StmtList;

	public:
		const std::list<const UnaryOperator*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitUnaryOperator(const UnaryOperator* UO) {
			if (UO && UO->getOpcode() == UnaryOperator::Opcode::UO_LNot) {
				if (auto E = UO->getSubExpr()) {
					if (auto IL = dyn_cast<IntegerLiteral>(E->IgnoreParenImpCasts()))
						StmtList.push_back(UO);
				}
			}
			return true;
		}
	};

	class ConstValueNotLogicOpChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void ConstValueNotLogicOpChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const {
	if (!D)
		return;

	const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);

	if (!FD || !FD->hasBody())
		return;

	FindNotExprVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto UO : Stmts) {
		reportBug(FD, UO->getOperatorLoc(), BR);
	}
}


void ConstValueNotLogicOpChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ConstValueNotLogicOpChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::ConstValueNotLogicOpChecker, lang);     
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ConstValueNotLogicOpChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerConstValueNotLogicOpChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ConstValueNotLogicOpChecker>();
}

bool ento::shouldRegisterConstValueNotLogicOpChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ConstValueNotLogicOpChecker>("anzu.ConstValueNotLogicOpChecker", "logical negation operation on constant values.", "");
}

#endif