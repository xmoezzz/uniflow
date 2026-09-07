#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/CheckerManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class StringOpFuncReturnUseChecker : public Checker< check::PreStmt<BinaryOperator> > {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void StringOpFuncReturnUseChecker::checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const {
	if (BO->getOpcode() != BinaryOperatorKind::BO_AddAssign)
		return;

	auto CE = dyn_cast<CallExpr>(BO->getRHS()->IgnoreParenCasts());
	if (!CE)
		return;

	auto FD = CE->getDirectCallee();
	if (!FD)
		return;

	auto Name = FD->getQualifiedNameAsString();
	if (Name == "sprintf" || Name == "snprintf"
		|| Name == "read" || Name == "strcpy"
		|| Name == "strcpy_s") {

		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}

		reportBug(FD, BO->getOperatorLoc(), C.getBugReporter());
	}
}

void StringOpFuncReturnUseChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "StringOpFuncReturnUseChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::StringOpFuncReturnUseChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "StringOpFuncReturnUseChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerStringOpFuncReturnUseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<StringOpFuncReturnUseChecker>();
}

bool ento::shouldRegisterStringOpFuncReturnUseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<StringOpFuncReturnUseChecker>("anzu.StringOpFuncReturnUseChecker", "", "");
}

#endif