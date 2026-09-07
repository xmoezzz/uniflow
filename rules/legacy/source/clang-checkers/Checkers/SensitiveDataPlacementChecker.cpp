#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class SensitiveDataPlacementChecker : public Checker<check::ASTDecl<RecordDecl>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTDecl(const RecordDecl* RD, AnalysisManager& Mgr, BugReporter& BR) const;

	private:
		// Check if the given field is an array type
		bool isCharArray(const FieldDecl* FD) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void SensitiveDataPlacementChecker::checkASTDecl(const RecordDecl* RD, AnalysisManager& Mgr, BugReporter& BR) const {
	const FieldDecl* PrevField = nullptr;
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::SensitiveDataPlacementChecker, lang);

	for (const auto* FD : RD->fields()) {
		if (isCharArray(FD))
			PrevField = FD;

		if (PrevField && FD->getType()->isPointerType()) {
			reportBug(findFunctionDecl(RD), Msg, PrevField->getBeginLoc(), BR);
		}
	}
}

bool SensitiveDataPlacementChecker::isCharArray(const FieldDecl* FD) const {
	if (!FD || !FD->getType()->isArrayType())
		return false;

	if (auto AT = dyn_cast<ArrayType>(FD->getType().getTypePtr())) {
		return AT->getElementType()->isCharType() || AT->getElementType()->isWideCharType();
	}

	return false;
}

void SensitiveDataPlacementChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "SensitiveDataPlacementChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "SensitiveDataPlacementChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSensitiveDataPlacementChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SensitiveDataPlacementChecker>();
}

bool ento::shouldRegisterSensitiveDataPlacementChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SensitiveDataPlacementChecker>("anzu.SensitiveDataPlacementChecker", "String placed before sensitive data in memory", "");
}

#endif