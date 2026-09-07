

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
	class IncludeFileAbsPathCheckerHandler : public checker::PreprocessorHandler {
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
			if (!FileName.empty()) {
				if (FileName.size() >= 2 && FileName[1] == ':' ||
					FileName[0] == '/') {
					Paths.push_back(FilenameRange.getBegin());
				}
			}
		}

	public:
		static const std::list<SourceLocation>& GetPaths() {
			return Paths;
		}
	};
	std::list<SourceLocation> IncludeFileAbsPathCheckerHandler::Paths;

	static checker::PreprocessorHandlerRegistry::Add<IncludeFileAbsPathCheckerHandler>
		Handler("IncludeFileAbsPathChecker", "IncludeFileAbsPathChecker");

	class IncludeFileAbsPathChecker : public Checker<check::EndOfTranslationUnit> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
			AnalysisManager& Mgr, BugReporter& BR) const {
			auto& Paths = IncludeFileAbsPathCheckerHandler::GetPaths();
			for (auto& Loc : Paths) {
				reportBug(Loc, BR);
			}
		}

		void reportBug(const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(this, "IncludeFileAbsPathChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::IncludeFileAbsPathChecker, lang);
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "IncludeFileAbsPathChecker"),
				DLoc);
			BR.emitReport(std::move(Report));
		}
	};
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerIncludeFileAbsPathChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<IncludeFileAbsPathChecker>();
}

bool ento::shouldRegisterIncludeFileAbsPathChecker(const CheckerManager& mgr) {
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
	registry.addChecker<IncludeFileAbsPathChecker>("anzu.IncludeFileAbsPathChecker", "It is prohibited to use absolute paths in the #include directive.", "");
}

#endif