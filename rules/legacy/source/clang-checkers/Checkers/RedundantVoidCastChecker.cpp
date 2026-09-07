#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FindCallExprVisitor
		: public RecursiveASTVisitor<FindCallExprVisitor> {
		std::list<const ExplicitCastExpr*> StmtList;
		int Level = 0;

	public:
		const std::list<const ExplicitCastExpr*>& getStmts() {
			return StmtList;
		}

	private:
		void CheckExpr(Expr* E) {
			
		}

	public:
		bool VisitExplicitCastExpr(ExplicitCastExpr* ECE) {
			if (ECE && ECE->getType()->isVoidType()) {
				if (auto E = ECE->getSubExpr()) {
					if (auto CE = dyn_cast<CallExpr>(E->IgnoreParens())) {
						if (auto FD = CE->getDirectCallee()) {
							if (FD->getReturnType()->isVoidType()) {
								StmtList.push_back(ECE);
							}
						}
					}
				}
			}
			return true;
		}
	};

	class RedundantVoidCastChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR, const std::string& Msg) const;
	};
} // end anonymous namespace

void RedundantVoidCastChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const {
	const FunctionDecl* FD = dyn_cast<FunctionDecl>(D);
	FindCallExprVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string m = ls->parseMsgs(anzulocalization::RedundantVoidCastChecker, lang);
	auto Stmts = Visitor.getStmts();
	for (auto ECE : Stmts) {
		std::string Msg;
		llvm::raw_string_ostream os(Msg);
		os << m;
		reportBug(FD, ECE->getBeginLoc(), BR, Msg);
	}
}

void RedundantVoidCastChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR, const std::string& Msg) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "RedundantVoidCastChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "RedundantVoidCastChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerRedundantVoidCastChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<RedundantVoidCastChecker>();
}

bool ento::shouldRegisterRedundantVoidCastChecker(const CheckerManager& mgr) {
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
	registry.addChecker<RedundantVoidCastChecker>("anzu.RedundantVoidCastChecker", "Checks for redundant casts to void for void functions", "");
}

#endif
