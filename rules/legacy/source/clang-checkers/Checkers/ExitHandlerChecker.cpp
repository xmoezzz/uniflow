#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <memory>
#include "../Utils.h"
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {

	class ExitFunctionVisitor : public ConstStmtVisitor<ExitFunctionVisitor, bool> {
		std::unordered_set<const FunctionDecl*> Visits;
		const Expr* ExceptExpr = nullptr;

	public:
		ExitFunctionVisitor(const FunctionDecl* FD) {
			Visits.insert(FD);
		}

		const Expr* GetExceptExpr() const {
			return ExceptExpr;
		}

		bool VisitCallExpr(const CallExpr* CE) {
			const FunctionDecl* FD = CE->getDirectCallee();
			if (!FD) return true;

			if (FD->isGlobal()) {
				auto FName = FD->getQualifiedNameAsString();
				if (FName == "exit" || FName == "_Exit" || FName == "quick_exit" || FName == "longjmp") {
					ExceptExpr = CE;
					return false;
				}
			}

			if (Visits.find(FD) == Visits.end()) {
				Visits.insert(FD);
				// Recursively visit the body of the callee
				if (const Stmt* Body = FD->getBody()) {
					return Visit(Body);
				}
			}

			return true;
		}

		bool VisitStmt(const Stmt* S) {
			for (const Stmt* Child : S->children()) {
				if (Child) {
					if (!Visit(Child)) {
						return false;
					}
				}
			}
			return true;
		}
	};

	class ExitHandlerChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void ExitHandlerChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
		if (Call.getNumArgs() < 1)
			return;

		const FunctionDecl* FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
		if (!FD)
			return;

		auto FName = FD->getQualifiedNameAsString();
		if (FName != "atexit" && FName != "at_quick_exit")
			return;

		const Expr* Arg = Call.getArgExpr(0);
		if (!Arg)
			return;

		if (const DeclRefExpr* DRE = dyn_cast_or_null<DeclRefExpr>(Arg->IgnoreParenCasts())) {
			if (auto CallbackD = DRE->getDecl()) {
				if (const FunctionDecl* CallbackFD = llvm::dyn_cast_or_null<FunctionDecl>(CallbackD)) {
					if (auto CallbackBody = CallbackFD->getBody()) {
						ExitFunctionVisitor Visitor(CallbackFD);
						Visitor.Visit(CallbackBody);
						if (auto ExceptExpr = Visitor.GetExceptExpr()) {
							reportBug(CallbackFD, ExceptExpr->getBeginLoc(), C.getBugReporter());
						}
					}
				}
			}
		}
	}

	void ExitHandlerChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "ExitHandlerChecker"));

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::ExitHandlerChecker, lang);       
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "ExitHandlerChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerExitHandlerChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ExitHandlerChecker>();
}

bool ento::shouldRegisterExitHandlerChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::C);
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
	registry.addChecker<ExitHandlerChecker>("anzu.ExitHandlerChecker", "", "");
}

#endif