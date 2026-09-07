

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
	class IncludeFilePathCheckerHandler : public checker::PreprocessorHandler {
	private:
		static std::list<SourceLocation> Paths;

	private:
		virtual void InclusionDirective(SourceLocation HashLoc,
			const Token& IncludeTok, StringRef FileName,
			bool IsAngled, CharSourceRange FilenameRange,
			OptionalFileEntryRef File,
			StringRef SearchPath, StringRef RelativePath,
			const Module* Imported,
			SrcMgr::CharacteristicKind FileType) override {
			if (FileName.find('\'') != StringRef::npos ||
				FileName.find('*') != StringRef::npos) {
				Paths.push_back(FilenameRange.getBegin());
			}
		}

	public:
		static const std::list<SourceLocation>& GetPaths() {
			return Paths;
		}
	};
	std::list<SourceLocation> IncludeFilePathCheckerHandler::Paths;

	static checker::PreprocessorHandlerRegistry::Add<IncludeFilePathCheckerHandler>
		Handler("IncludeFilePathChecker", "IncludeFilePathChecker");

	class IncludeFilePathChecker : public Checker<check::EndOfTranslationUnit> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
			AnalysisManager& Mgr, BugReporter& BR) const {
			auto& Paths = IncludeFilePathCheckerHandler::GetPaths();
			for (auto& Loc : Paths) {
				reportBug(Loc, BR);
			}
		}

		void reportBug(const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(this, "IncludeFilePathChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::IncludeFilePathChecker, lang);
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "IncludeFilePathChecker"), DLoc);
			BR.emitReport(std::move(Report));
		}
	};
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerIncludeFilePathChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<IncludeFilePathChecker>();
}

bool ento::shouldRegisterIncludeFilePathChecker(const CheckerManager& mgr) {
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
	registry.addChecker<IncludeFilePathChecker>("anzu.IncludeFilePathChecker", "The use of characters such as \"'\", \"\\\", and \"/*\" is prohibited in header file names.", "");
}

#endif