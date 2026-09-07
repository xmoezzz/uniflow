#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class SizeofParamArrayChecker : public Checker<check::PreStmt<UnaryExprOrTypeTraitExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const UnaryExprOrTypeTraitExpr* UE, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void SizeofParamArrayChecker::checkPreStmt(const UnaryExprOrTypeTraitExpr* UE, CheckerContext& C) const {
	if (UE->getKind() != UETT_SizeOf)
		return;

	if (!UE->isArgumentType()) {
		if (const Expr* E = UE->getArgumentExpr()) {
			if (auto DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenCasts())) {
				if (auto VD = DRE->getDecl()) {
					if (auto PVD = dyn_cast<ParmVarDecl>(VD)) {
						if (PVD->getOriginalType()->isArrayType()) {
							const FunctionDecl* FD = nullptr;
							if (auto ADC = C.getCurrentAnalysisDeclContext()) {
								FD = dyn_cast<FunctionDecl>(ADC->getDecl());
							}
							reportBug(FD, E->getBeginLoc(), C.getBugReporter());
						}
					}
				}
			}
		}
	}
}

void SizeofParamArrayChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "SizeofParamArrayChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::SizeofParamArrayChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "SizeofParamArrayChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSizeofParamArrayChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SizeofParamArrayChecker>();
}

bool ento::shouldRegisterSizeofParamArrayChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SizeofParamArrayChecker>("anzu.SizeofParamArrayChecker", "", "");
}

#endif