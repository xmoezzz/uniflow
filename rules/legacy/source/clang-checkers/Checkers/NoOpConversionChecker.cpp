#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindCastExprVisitor
		: public RecursiveASTVisitor<FindCastExprVisitor> {
		std::list<const ExplicitCastExpr*> StmtList;

	public:
		const std::list<const ExplicitCastExpr*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitExplicitCastExpr(const ExplicitCastExpr* ECE) {
			if (ECE) {
				StmtList.push_back(ECE);
			}
			return true;
		}
	};

	class NoOpConversionChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		const DeclRefExpr* findGlobalCtrlVar(const Expr* Cond, const Expr* Inc) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void NoOpConversionChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	const FunctionDecl* FD = dyn_cast<FunctionDecl>(D);
	FindCastExprVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto S : Stmts) {
		if (auto Sub = S->getSubExpr()) {
			const auto SourceTy = Sub->IgnoreParenImpCasts()->getType().getCanonicalType();
			const auto TargetTy = S->getType().getCanonicalType();
			if (SourceTy == TargetTy) {
				reportBug(FD, S->getBeginLoc(), BR);
			}
		}
	}
}

void NoOpConversionChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;

	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "NoOpConversionChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::NoOpConversionChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "NoOpConversionChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerNoOpConversionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<NoOpConversionChecker>();
}

bool ento::shouldRegisterNoOpConversionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<NoOpConversionChecker>("anzu.NoOpConversionChecker", "Disable type conversion has no effect", "");
}

#endif