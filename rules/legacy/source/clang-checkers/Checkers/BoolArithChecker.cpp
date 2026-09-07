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
	class FindBoolArithVisitor
		: public RecursiveASTVisitor<FindBoolArithVisitor> {
		std::list<const Expr*> StmtList;

	public:
		const std::list<const Expr*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitBinaryOperator(const BinaryOperator* BO) {
			if (BO->isAdditiveOp() || BO->isShiftOp()) {
				auto LHS = BO->getLHS()->IgnoreParenImpCasts();
				if (LHS->getType()->isBooleanType()) {
					StmtList.push_back(LHS);
				}
				auto RHS = BO->getRHS()->IgnoreParenImpCasts();
				if (RHS->getType()->isBooleanType()) {
					StmtList.push_back(RHS);
				}
			}
			return true;
		}
		bool VisitUnaryOperator(const UnaryOperator* UO) {
			if (UO->isIncrementDecrementOp()) {
				auto Sub = UO->getSubExpr()->IgnoreParenImpCasts();
				if (Sub->getType()->isBooleanType()) {
					StmtList.push_back(Sub);
				}
			}
			return true;
		}
	};

	class BoolArithChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void BoolArithChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const {
	if (!D)
		return;

	const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);

	if (!FD || !FD->hasBody())
		return;

	FindBoolArithVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto S : Stmts) {
		reportBug(FD, S->getBeginLoc(), BR);
	}
}

void BoolArithChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "BoolArithChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::BoolArithChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(*BT, Msg, createRuleExtData(1, "BoolArithChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}


/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBoolArithChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BoolArithChecker>();
}

bool ento::shouldRegisterBoolArithChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BoolArithChecker>("anzu.BoolArithChecker", "Disable boolean arithmetic operations", "");
}

#endif