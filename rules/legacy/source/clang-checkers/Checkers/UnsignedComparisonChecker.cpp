#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FindBinaryOperatorExprVisitor
		: public RecursiveASTVisitor<FindBinaryOperatorExprVisitor> {
		std::list<const BinaryOperator*> StmtList;

	public:
		const std::list<const BinaryOperator*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitBinaryOperator(const BinaryOperator* BO) {
			if (BO) {
				StmtList.push_back(BO);
			}
			return true;
		}
	};

	class UnsignedComparisonChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
		bool isZero(const Expr* E) const;
	};

	void UnsignedComparisonChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
		BugReporter& BR) const {
		if (!D)
			return;

		const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);
		if (!FD || !FD->hasBody())
			return;

		FindBinaryOperatorExprVisitor Visitor;
		Visitor.TraverseDecl(const_cast<Decl*>(D));
		auto Stmts = Visitor.getStmts();
		for (auto BO : Stmts) {
			auto OP = BO->getOpcode();
			if (OP == BinaryOperator::Opcode::BO_GT || OP == BinaryOperator::Opcode::BO_LE) {
				if (isZero(BO->getLHS()) && BO->getRHS()->getType()->isUnsignedIntegerType()) {
					reportBug(FD, BO->getOperatorLoc(), BR);
				}
			}
			else if (OP == BinaryOperator::Opcode::BO_LT || OP == BinaryOperator::Opcode::BO_GE) {
				if (isZero(BO->getRHS()) && BO->getLHS()->getType()->isUnsignedIntegerType()) {
					reportBug(FD, BO->getOperatorLoc(), BR);
				}
			}
		}
	}

	void UnsignedComparisonChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "UnsignedComparisonChecker"));
		}

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::UnsignedComparisonChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg,
			createRuleExtData(1, "UnsignedComparisonChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}

	bool UnsignedComparisonChecker::isZero(const Expr* E) const {
		if (!E) {
			return false;
		}

		E = E->IgnoreParenCasts();
		if (auto IL = dyn_cast<IntegerLiteral>(E)) {
			return IL->getValue() == 0;
		}

		return false;
		}

}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUnsignedComparisonChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UnsignedComparisonChecker>();
}

bool ento::shouldRegisterUnsignedComparisonChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UnsignedComparisonChecker>("anzu.UnsignedComparisonChecker", "Prohibit comparisons of unsigned integers with 0 using >= or <", "");
}

#endif