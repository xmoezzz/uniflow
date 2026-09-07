#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include <clang/AST/ExprCXX.h>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class CastPreferenceChecker : public Checker<check::PreStmt<CXXStaticCastExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const CXXStaticCastExpr* CE, CheckerContext& C) const;
		const CXXRecordDecl* getRecordDecl(const QualType& QT) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void CastPreferenceChecker::checkPreStmt(const CXXStaticCastExpr* CE, CheckerContext& C) const {
	const auto* SrcType = getRecordDecl(CE->getSubExpr()->getType());
	const auto* DestType = getRecordDecl(CE->getType());
	if (!SrcType || !DestType || SrcType == DestType) {
		return;
	}

	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}
	reportBug(FD, CE->getBeginLoc(), C.getBugReporter());
}

const CXXRecordDecl* CastPreferenceChecker::getRecordDecl(const QualType& QT) const {
	if (auto PT = QT->getAs<PointerType>()) {
		if (const RecordType* RT = PT->getPointeeType()->getAs<RecordType>()) {
			return dyn_cast<CXXRecordDecl>(RT->getDecl());
		}
	}
	if (auto PT = QT->getAs<ReferenceType>()) {
		if (const RecordType* RT = PT->getPointeeType()->getAs<RecordType>()) {
			return dyn_cast<CXXRecordDecl>(RT->getDecl());
		}
	}
	return nullptr;
}

void CastPreferenceChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "CastPreferenceChecker"));

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CastPreferenceChecker, lang);
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CastPreferenceChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCastPreferenceChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CastPreferenceChecker>();
}

bool ento::shouldRegisterCastPreferenceChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CastPreferenceChecker>(
		"anzu.CastPreferenceChecker",
		"Prefer dynamic_cast over static_cast over reinterpret_cast",
		"");
}

#endif
