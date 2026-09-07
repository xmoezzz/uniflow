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
	class FindForStmtsVisitor
		: public RecursiveASTVisitor<FindForStmtsVisitor> {
		std::list<const ForStmt*> Stmts;

	public:
		const std::list<const ForStmt*>& getStmts() {
			return Stmts;
		}

	public:
		bool VisitForStmt(const ForStmt* B) {
			if (B) {
				Stmts.push_back(B);
			}
			return true;
		}
	};

	class FloatingPointLoopVariableChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		FloatingPointLoopVariableChecker() {}

		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

		void analyzeForStmt(const FunctionDecl* FD, const ForStmt* FS, BugReporter& BR) const;
		void analyzeBinaryOperator(const FunctionDecl* FD, const BinaryOperator* BO, BugReporter& BR) const;
		void analyzeVarDecl(const FunctionDecl* FD, const VarDecl* VD, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
} // end anonymous namespace

void FloatingPointLoopVariableChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	auto FD = dyn_cast<FunctionDecl>(D);
	FindForStmtsVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	AnalysisDeclContext* AC = Mgr.getAnalysisDeclContext(D);
	auto Stmts = Visitor.getStmts();
	for (auto S : Stmts) {
		analyzeForStmt(FD, S, BR);
	}
}

void FloatingPointLoopVariableChecker::analyzeForStmt(const FunctionDecl* FD, const ForStmt* FS, BugReporter& BR) const {
	if (auto Init = FS->getInit()) {
		if (const DeclStmt* DS = dyn_cast_or_null<DeclStmt>(Init)) {
			for (const Decl* D : DS->decls()) {
				if (const VarDecl* VD = llvm::dyn_cast_or_null<VarDecl>(D)) {
					analyzeVarDecl(FD, VD, BR);
				}
			}
		}
		else if (auto E = dyn_cast<Expr>(Init)) {
			if (auto BO = dyn_cast<BinaryOperator>(E->IgnoreParenImpCasts())) {
				analyzeBinaryOperator(FD, BO, BR);
			}
		}
	}
}

void FloatingPointLoopVariableChecker::analyzeBinaryOperator(const FunctionDecl* FD, const BinaryOperator* BO, BugReporter& BR) const {
	if (BO->getOpcode() == BO_Assign) {
		if (auto DRE = dyn_cast<DeclRefExpr>(BO->getLHS()->IgnoreParenImpCasts())) {
			if (const auto* VD = dyn_cast<VarDecl>(DRE->getDecl())) {
				analyzeVarDecl(FD, VD, BR);
			}
		}
	}
	else if (BO->getOpcode() == BO_Comma) {
		if (auto SBO = dyn_cast<BinaryOperator>(BO->getLHS()->IgnoreParenImpCasts())) {
			analyzeBinaryOperator(FD, SBO, BR);
		}
		if (auto SBO = dyn_cast<BinaryOperator>(BO->getRHS()->IgnoreParenImpCasts())) {
			analyzeBinaryOperator(FD, SBO, BR);
		}
	}
}

void FloatingPointLoopVariableChecker::analyzeVarDecl(const FunctionDecl* FD, const VarDecl* VD, BugReporter& BR) const {
	if (VD->getType()->isFloatingType()) {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::FloatingPointLoopVariableChecker, lang);
		reportBug(FD, Msg, VD->getBeginLoc(), BR);
	}
}

void FloatingPointLoopVariableChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "FloatingPointLoopVariableChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "FloatingPointLoopVariableChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFloatingPointLoopVariableChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FloatingPointLoopVariableChecker>();
}

bool ento::shouldRegisterFloatingPointLoopVariableChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FloatingPointLoopVariableChecker>("anzu.FloatingPointLoopVariableChecker", "", "");
}

#endif

