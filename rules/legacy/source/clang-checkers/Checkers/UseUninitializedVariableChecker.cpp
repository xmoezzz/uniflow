#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class UseUninitializedVariableChecker : public Checker<check::PreStmt<DeclStmt>,
		check::PreStmt<ReturnStmt>,
		check::PreStmt<BinaryOperator>,
		check::PreStmt<UnaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const DeclStmt* DS, CheckerContext& C) const;
		void checkPreStmt(const ReturnStmt* RS, CheckerContext& C) const;
		void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const;
		void checkPreStmt(const UnaryOperator* UO, CheckerContext& C) const;

	private:
		void analyze(const Expr* E, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void UseUninitializedVariableChecker::checkPreStmt(const DeclStmt* DS, CheckerContext& C) const {
	for (auto D : DS->decls()) {
		if (D) {
			if (auto VD = dyn_cast<VarDecl>(D)) {
				if (auto Init = VD->getInit()) {
					analyze(Init, C);
				}
			}
		}
	}
}

void UseUninitializedVariableChecker::checkPreStmt(const ReturnStmt* RS, CheckerContext& C) const {
	if (auto R = RS->getRetValue()) {
		analyze(R, C);
	}
}

void UseUninitializedVariableChecker::checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const {
	if (auto R = BO->getRHS()) {
		analyze(BO->getRHS(), C);
	}
}

void UseUninitializedVariableChecker::checkPreStmt(const UnaryOperator* UO, CheckerContext& C) const {
	if (UO->getOpcode() == UO_Deref) {
		analyze(UO->getSubExpr(), C);
	}
}

void UseUninitializedVariableChecker::analyze(const Expr* E, CheckerContext& C) const {
	if (C.getASTContext().HasSyntaxErrors()) {
		return;
	}

	if (!E) {
		return;
	}

	if (auto DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts()->IgnoreParenCasts())) {
		const VarDecl* VD = llvm::dyn_cast_or_null<VarDecl>(DRE->getDecl());
		if (!VD || !VD->hasLocalStorage() || VD->isExceptionVariable())
			return;

		ProgramStateRef State = C.getState();
		const LocationContext* LCtx = C.getLocationContext();
		const MemRegion* R = State->getRegion(VD, LCtx);

		if (State->getSVal(R, VD->getType()).isUndef()) {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::UseUninitializedVariableChecker, lang);

			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, Msg, E->getBeginLoc(), C.getBugReporter());
		}
	}
}

void UseUninitializedVariableChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "UseUninitializedVariableChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "UseUninitializedVariableChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUseUninitializedVariableChecker(CheckerManager& Mgr) {
	//Mgr.registerChecker<UseUninitializedVariableChecker>();
}

bool ento::shouldRegisterUseUninitializedVariableChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UseUninitializedVariableChecker>("anzu.UseUninitializedVariableChecker", "Variable must be initialized before use", "");
}

#endif