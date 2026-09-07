#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/Basic/Builtins.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"


using namespace clang;
using namespace ento;

namespace {
	static constexpr taint::TaintTagType EOF_TAINT_VAL = taint::TaintTagGeneric + 0x1000;

	class FindBinaryOperatorVisitor
		: public RecursiveASTVisitor<FindBinaryOperatorVisitor> {
		std::list<const BinaryOperator*> ExprList;

	public:
		const std::list<const BinaryOperator*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitBinaryOperator(const BinaryOperator* BO) {
			if (BO) {
				ExprList.push_back(BO);
			}
			return true;
		}
	};

	class EOFComparisonChecker : public Checker<check::PostStmt<CallExpr>, check::PreStmt<BinaryOperator>, check::BranchCondition> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPostStmt(const CallExpr* CE, CheckerContext& C) const {
			// Identify calls to getchar, getwc, etc.
			const FunctionDecl* FD = C.getCalleeDecl(CE);
			if (!FD) return;

			StringRef FuncName = C.getCalleeName(FD);
			if (FuncName != "getchar" && FuncName != "getwc") return;

			// Add taint to the return value.
			ProgramStateRef State = C.getState();
			SymbolRef Sym = C.getSVal(CE).getAsSymbol();
			if (Sym) {
				State = taint::addTaint(State, Sym, EOF_TAINT_VAL);
				C.addTransition(State);
			}
		}

		void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const {
			if (BO->getOpcode() != BO_EQ && BO->getOpcode() != BO_NE)
				return;

			ProgramStateRef State = C.getState();
			const Expr* LHS = BO->getLHS();
			const Expr* RHS = BO->getRHS();

			// Check if either side of the comparison is tainted and the other side is EOF or WEOF.
			if ((isTainted(State, C.getSVal(LHS)) && isEOF(RHS, C)) ||
				(isTainted(State, C.getSVal(RHS)) && isEOF(LHS, C))) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::EOFComparisonChecker, lang);

				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				reportBug(FD, Msg, BO->getOperatorLoc(), C.getBugReporter());
			}
		}

		void checkBranchCondition(const Stmt* Condition, CheckerContext& C) const {
			FindBinaryOperatorVisitor Visitor;
			Visitor.TraverseStmt(const_cast<Stmt*>(Condition));
			auto& Exprs = Visitor.getExprs();
			for (auto BO : Exprs) {
				checkPreStmt(BO, C);
			}
		}

	private:
		bool isTainted(ProgramStateRef State, SVal Val) const {
			return taint::isTainted(State, Val.getAsSymbol(), EOF_TAINT_VAL);
		}

		bool isEOF(const Expr* E, CheckerContext& C) const {
			E = E->IgnoreParenImpCasts();
			if (IsConstantExpr(E)) {
				if (auto CI = C.getSVal(E).getAs<nonloc::ConcreteInt>()) {
					if (auto Value = CI->getAsInteger()) {
						auto V = Value->getSExtValue();
						return V == EOF || V == WEOF;
					}
				}
			}
			return false;
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "EOFComparisonChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "EOFComparisonChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerEOFComparisonChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<EOFComparisonChecker>();
}

bool ento::shouldRegisterEOFComparisonChecker(const CheckerManager& mgr) {
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
	registry.addChecker<EOFComparisonChecker>("anzu.EOFComparisonChecker", "", "");
}

#endif