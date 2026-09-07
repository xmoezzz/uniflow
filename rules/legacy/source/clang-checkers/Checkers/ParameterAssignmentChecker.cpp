#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class ParameterAssignmentChecker : public Checker<check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void ParameterAssignmentChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (B->getOpcode() != BO_Assign) return;

	const Expr* LHS = B->getLHS()->IgnoreParenImpCasts();

	if (const DeclRefExpr* DRE = llvm::dyn_cast_or_null<DeclRefExpr>(LHS)) {
		if (const ParmVarDecl* PVD = llvm::dyn_cast_or_null<ParmVarDecl>(DRE->getDecl())) {
			if (PVD->getType()->isPointerType()) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::ParameterAssignmentChecker, lang);

				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				reportBug(FD, Msg, B->getOperatorLoc(), C.getBugReporter());
			}
		}
	}
}

void ParameterAssignmentChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "ParameterAssignmentChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ParameterAssignmentChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerParameterAssignmentChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ParameterAssignmentChecker>();
}

bool ento::shouldRegisterParameterAssignmentChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ParameterAssignmentChecker>("anzu.ParameterAssignmentChecker", "Prohibit assignment to parameter pointers.", "");
}

#endif
