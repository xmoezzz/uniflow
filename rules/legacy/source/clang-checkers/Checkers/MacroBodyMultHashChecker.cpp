#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class MacroBodyMultHashChecker : public Checker<check::EndOfTranslationUnit> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
			AnalysisManager& Mgr,
			BugReporter& BR) const {

			Preprocessor& PP = Mgr.getPreprocessor();
			for (auto it = PP.macro_begin(); it != PP.macro_end(); ++it) {
				if (auto II = it->first) {
					if (MacroInfo* MI = PP.getMacroInfo(II)) {
						if (Mgr.getSourceManager().isInSystemMacro(MI->getDefinitionLoc()) ||
							Mgr.getSourceManager().isInSystemHeader(MI->getDefinitionLoc())) {
							continue;
						}
						checkMacroInfo(Mgr, BR, MI);
					}
				}
			}
		}

		bool checkMacroInfo(AnalysisManager& Mgr, BugReporter& BR, MacroInfo* MI) const {
			if (!MI) {
				return true;
			}

			if (!existMacroBodyMultHasHash(MI)) {
				return true;
			}

			reportBug(MI->getDefinitionLoc(), BR);

			return false;
		}

		bool existMacroBodyMultHasHash(MacroInfo* MI) const {
			if (MI->params().empty()) {
				return false;
			}

			int count = 0;
			for (auto t : MI->tokens()) {
				if (t.getKind() == tok::hash ||
					t.getKind() == tok::hashhash) {
					if (++count >= 2) {
						return true;
					}
				}
			}

			return false;
		}

		void reportBug(const SourceLocation& Loc, BugReporter& BR) const {
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "MacroBodyMultHashChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::MacroBodyMultHashChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "MacroBodyMultHashChecker"), DLoc);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMacroBodyMultHashChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MacroBodyMultHashChecker>();
}

bool ento::shouldRegisterMacroBodyMultHashChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MacroBodyMultHashChecker>("anzu.MacroBodyMultHashChecker", "Prohibit using multiple '#' or '##' in the same macro.", "");
}

#endif