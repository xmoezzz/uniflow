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
	class TimeOpChecker : public Checker< check::PreStmt<BinaryOperator> > {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const;
		bool IsTimeType(const QualType& QT) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void TimeOpChecker::checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const {
	if (!BO->isAdditiveOp() &&
		BO->getOpcode() != BinaryOperatorKind::BO_AddAssign &&
		BO->getOpcode() != BinaryOperatorKind::BO_SubAssign)
		return;

	if (IsTimeType(BO->getLHS()->IgnoreParenCasts()->getType())) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}

		reportBug(FD, BO->getLHS()->IgnoreParenCasts()->getBeginLoc(), C.getBugReporter());
	}
	else if (IsTimeType(BO->getRHS()->IgnoreParenCasts()->getType())) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}

		reportBug(FD, BO->getRHS()->IgnoreParenCasts()->getBeginLoc(), C.getBugReporter());
	}
}

bool TimeOpChecker::IsTimeType(const QualType& QT) const {
	auto Name = QT.getAsString();
	if (Name != "time_t")
		return false;

	return true;
}

void TimeOpChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "TimeOpChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::TimeOpChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "TimeOpChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerTimeOpChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<TimeOpChecker>();
}

bool ento::shouldRegisterTimeOpChecker(const CheckerManager& mgr) {
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
	registry.addChecker<TimeOpChecker>("anzu.TimeOpChecker", "", "");
}

#endif