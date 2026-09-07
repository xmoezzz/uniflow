#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class ArrayVarBoundDefinedChecker : public Checker<check::ASTDecl<VarDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void ArrayVarBoundDefinedChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!VD)
		return;

	if (isa<ParmVarDecl>(VD))
		return;

	if (auto TSI = VD->getTypeSourceInfo()) {
		if (TSI->getType()->isIncompleteArrayType()) {

			auto ls = anzulocalization::LocaleSetting::getInstance();
		    uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		    std::string fmt = ls->parseMsgs(anzulocalization::ArrayVarBoundDefinedChecker, lang);
			std::string vd = VD->getName().str();

		    std::string Msg = std::vformat(fmt, std::make_format_args(vd));
			reportBug(findFunctionDecl(VD), Msg, VD->getBeginLoc(), BR);
		}
	}
}

void ArrayVarBoundDefinedChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "ArrayVarBoundDefinedChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ArrayVarBoundDefinedChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerArrayVarBoundDefinedChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ArrayVarBoundDefinedChecker>();
}

bool ento::shouldRegisterArrayVarBoundDefinedChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ArrayVarBoundDefinedChecker>("anzu.ArrayVarBoundDefinedChecker", "Array definitions are prohibited from lacking explicit boundary limits.", "");
}

#endif