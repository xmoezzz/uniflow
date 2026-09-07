#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class ExternVarInFunctionBodyChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void ExternVarInFunctionBodyChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::ExternVarInFunctionBodyChecker, lang);
	if (auto FD = dyn_cast<FunctionDecl>(D)) {
		if (FD->hasBody()) {
			for (auto CD : FD->decls()) {
				if (const VarDecl* CVD = dyn_cast<VarDecl>(CD)) {
					if (CVD->hasExternalStorage()) {
						auto Name = CVD->getNameAsString();
						std::string Msg = std::vformat(fmt, std::make_format_args(Name));
						reportBug(D, Msg, CVD->getBeginLoc(), BR);
					}
				}
			}
		}
	}
}

void ExternVarInFunctionBodyChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ExternVarInFunctionBodyChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ExternVarInFunctionBodyChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerExternVarInFunctionBodyChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ExternVarInFunctionBodyChecker>();
}

bool ento::shouldRegisterExternVarInFunctionBodyChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ExternVarInFunctionBodyChecker>("anzu.ExternVarInFunctionBodyChecker", "It is prohibited to use external declarations within a function body.", "");
}

#endif