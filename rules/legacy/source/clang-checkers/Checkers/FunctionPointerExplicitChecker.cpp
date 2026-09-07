#include "clang/AST/ASTContext.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class FunctionPointerExplicitChecker : public Checker<check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void FunctionPointerExplicitChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (B->getOpcode() != BO_Assign) return;

	const Expr* RHS = B->getRHS()->IgnoreParenImpCasts();
	const Expr* LHS = B->getLHS()->IgnoreParenImpCasts();

	if (const DeclRefExpr* DRE = llvm::dyn_cast_or_null<DeclRefExpr>(RHS)) {
		if (const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(DRE->getDecl())) {
			if (!isa<UnaryOperator>(RHS)) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::FunctionPointerExplicitChecker, lang);

				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				reportBug(FD, Msg, B->getOperatorLoc(), C.getBugReporter());
			}
		}
	}
}

void FunctionPointerExplicitChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "FunctionPointerExplicitChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "FunctionPointerExplicitChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFunctionPointerExplicitChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FunctionPointerExplicitChecker>();
}

bool ento::shouldRegisterFunctionPointerExplicitChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FunctionPointerExplicitChecker>("anzu.FunctionPointerExplicitChecker", "The usage of function pointers must be explicitly indicated with the '&' operator.", "");
}

#endif
