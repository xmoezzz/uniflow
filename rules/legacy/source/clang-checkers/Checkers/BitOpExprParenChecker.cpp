#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <unordered_set>
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FindBitExprVisitor
		: public RecursiveASTVisitor<FindBitExprVisitor> {
		std::list<const BinaryOperator*> ExprList;

	public:
		const std::list<const BinaryOperator*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitBinaryOperator(const BinaryOperator* B) {
			if (B->isBitwiseOp()) {
				if (auto LHS = B->getLHS()->IgnoreImpCasts()) {
					if (auto RHS = B->getRHS()->IgnoreImpCasts()) {
						if (auto LHS_BO = dyn_cast<BinaryOperator>(LHS)) {
							if (!LHS_BO->isBitwiseOp()) {
								ExprList.push_back(B);
								return true;
							}
						}
						if (auto RHS_BO = dyn_cast<BinaryOperator>(RHS)) {
							if (!RHS_BO->isBitwiseOp()) {
								ExprList.push_back(B);
								return true;
							}
						}
					}
				}
			}
			return true;
		}
	};

	class BitOpExprParenChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void BitOpExprParenChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
		BugReporter& BR) const
	{
		auto FD = dyn_cast<FunctionDecl>(D);
		FindBitExprVisitor Visitor;
		Visitor.TraverseDecl(const_cast<Decl*>(D));
		auto& Exprs = Visitor.getExprs();
		for (auto B : Exprs) {
			reportBug(FD, B->getOperatorLoc(), BR);
		}
	}

	void BitOpExprParenChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;

		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "BitOpExprParenChecker"));
		}

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::BitOpExprParenChecker, lang);
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "BitOpExprParenChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBitOpExprParenChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BitOpExprParenChecker>();
}

bool ento::shouldRegisterBitOpExprParenChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BitOpExprParenChecker>("anzu.BitOpExprParenChecker", "", "");
}

#endif