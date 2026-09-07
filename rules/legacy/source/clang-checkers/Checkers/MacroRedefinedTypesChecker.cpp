#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class MacroRedefinedTypesChecker : public Checker<check::EndOfTranslationUnit> {
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

			if (!isRedefineTypesMacro(MI, BR)) {
				return true;
			}

			reportBug(MI->getDefinitionLoc(), BR);

			return false;
		}

		bool isRedefineTypesMacro(MacroInfo* MI, BugReporter& BR) const {
			if (MI->tokens().empty()) {
				return false;
			}

			for (auto t : MI->tokens()) {
				if (!isTypeKeywords(t)) {
					return false;
				}
			}

			return true;
		}

		bool isTypeKeywords(const Token& t) const {
			return t.getKind() == tok::kw_void ||
				t.getKind() == tok::kw_bool ||
				t.getKind() == tok::kw_char ||
				t.getKind() == tok::kw_wchar_t ||
				t.getKind() == tok::kw_char16_t ||
				t.getKind() == tok::kw_char32_t ||
				t.getKind() == tok::kw_short ||
				t.getKind() == tok::kw_int ||
				t.getKind() == tok::kw_long ||
				t.getKind() == tok::kw_float ||
				t.getKind() == tok::kw_double ||
				t.getKind() == tok::kw_signed ||
				t.getKind() == tok::kw_unsigned ||
				t.getKind() == tok::kw_mutable ||
				t.getKind() == tok::kw_volatile ||
				t.getKind() == tok::kw_static ||
				t.getKind() == tok::kw_register ||
				t.getKind() == tok::star ||
				t.getKind() == tok::l_paren ||
				t.getKind() == tok::r_paren;
		}

		void reportBug(const SourceLocation& Loc, BugReporter& BR) const {
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "MacroRedefinedTypesChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::MacroRedefinedTypesChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "MacroRedefinedTypesChecker"), DLoc);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMacroRedefinedTypesChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MacroRedefinedTypesChecker>();
}

bool ento::shouldRegisterMacroRedefinedTypesChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MacroRedefinedTypesChecker>("anzu.MacroRedefinedTypesChecker", "Prohibit redefining reserved keywords.", "");
}

#endif