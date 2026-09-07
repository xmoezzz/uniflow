#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class CvQualificationChecker : public Checker<check::PreStmt<CastExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const CastExpr* CE, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
		bool isSameConstExpr(const QualType& SrcQT, const QualType& DstQT) const;
	};

}

void CvQualificationChecker::checkPreStmt(const CastExpr* CE, CheckerContext& C) const {
	QualType SrcType = CE->getSubExpr()->getType();
	QualType DstType = CE->getType();
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());

	// Check const qualification violation.
	if (!isSameConstExpr(SrcType, DstType)) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}
		std::string Msg = ls->parseMsgs(anzulocalization::CvQualificationChecker, lang, 0);
		reportBug(FD, Msg, CE->getBeginLoc(), C.getBugReporter());
		return;
	}

	// Check volatile qualification violation.
	if (SrcType.isVolatileQualified() && !DstType.isVolatileQualified()) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}
		std::string Msg = ls->parseMsgs(anzulocalization::CvQualificationChecker, lang, 1);
		reportBug(FD, Msg, CE->getBeginLoc(), C.getBugReporter());
	}
}

bool CvQualificationChecker::isSameConstExpr(const QualType& SrcQT, const QualType& DstQT) const {
	if (auto SrcPT = dyn_cast<PointerType>(SrcQT)) {
		if (!SrcPT->getPointeeType().isConstQualified()) {
			return true;
		}
	}
	else if (auto SrcRT = dyn_cast<ReferenceType>(SrcQT)) {
		if (!SrcRT->getPointeeType().isConstQualified()) {
			return true;
		}
	}
	else if (!isa<ConstantArrayType>(SrcQT)) {
		return true;
	}

	if (auto DstPT = dyn_cast<PointerType>(DstQT)) {
		return DstPT->getPointeeType().isConstQualified();
	}

	if (auto DstRT = dyn_cast<ReferenceType>(DstQT)) {
		return DstRT->getPointeeType().isConstQualified();
	}

	return true;
}

void CvQualificationChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "CvQualificationChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CvQualificationChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCvQualificationChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CvQualificationChecker>();
}

bool ento::shouldRegisterCvQualificationChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::CPP);
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
	registry.addChecker<CvQualificationChecker>("anzu.CvQualificationChecker", "Check for access to cv-qualified object through cv-unqualified type", "");
}

#endif