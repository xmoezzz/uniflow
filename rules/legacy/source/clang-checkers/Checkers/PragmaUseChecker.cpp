

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"
#include "CheckerHandlerRegistry.h"
#include <list>

using namespace clang;
using namespace ento;

namespace {
	class PragmaUseCheckerHandler : public checker::PreprocessorHandler {
	private:
		static std::list<SourceLocation> Pragmas;

	private:
		virtual void PragmaDirective(SourceLocation Loc,
			PragmaIntroducerKind Introducer) override {
			Pragmas.push_back(Loc);
		}

	public:
		static const std::list<SourceLocation>& GetPragmas() {
			return Pragmas;
		}
	};
	std::list<SourceLocation> PragmaUseCheckerHandler::Pragmas;

	static checker::PreprocessorHandlerRegistry::Add<PragmaUseCheckerHandler>
		Handler("PragmaUseChecker", "PragmaUseChecker");

	class PragmaUseChecker : public Checker<check::EndOfTranslationUnit> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
			AnalysisManager& Mgr, BugReporter& BR) const {
			auto& Pragmas = PragmaUseCheckerHandler::GetPragmas();
			for (auto& Loc : Pragmas) {
				reportBug(Loc, BR);
			}
		}

		void reportBug(const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
					
			if (!BT) {
				BT.reset(new BuiltinBug(this, "PragmaUseChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::PragmaUseChecker, lang);
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg,
				createRuleExtData(1, "PragmaUseChecker"),
				DLoc);
			BR.emitReport(std::move(Report));
		}
	};
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPragmaUseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PragmaUseChecker>();
}

bool ento::shouldRegisterPragmaUseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PragmaUseChecker>("anzu.PragmaUseChecker", "Use '#pragma' with caution.", "");
}

#endif