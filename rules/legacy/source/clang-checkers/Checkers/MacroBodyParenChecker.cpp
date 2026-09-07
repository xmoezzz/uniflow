#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class MacroBodyParenChecker : public Checker<check::EndOfTranslationUnit> {
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

			if (checkMacroBodyHasParen(MI)) {
				return true;
			}

			reportBug(MI->getDefinitionLoc(), BR);

			return false;
		}

		bool checkMacroBodyHasParen(MacroInfo* MI) const {
			if (MI->params().empty()) {
				return true;
			}

			if (MI->tokens().size() == 0) {
				return true;
			}

			bool HasSemi = false;
			for (auto token : MI->tokens()) {
				if (token.getKind() == tok::semi) {
					HasSemi = true;
					break;
				}
			}
			if (!HasSemi) {
				return true;
			}

			if (MI->tokens().size() == 1) {
				return !MI->tokens_begin()->isAnyIdentifier();
			}

			auto TokenBegin = MI->tokens_begin();
			auto TokenEnd = MI->tokens_end();
			--TokenEnd;

			if (TokenEnd->getKind() == tok::semi) {
				--TokenEnd;
			}

			if (TokenBegin->getKind() == tok::l_paren &&
				TokenEnd->getKind() == tok::r_paren) {
				return true;
			}

			if (TokenBegin->getKind() == tok::l_brace &&
				TokenEnd->getKind() == tok::r_brace) {
				return true;
			}

			return false;
		}

		void reportBug(const SourceLocation& Loc, BugReporter& BR) const {
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "MacroBodyParenChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::MacroBodyParenChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "MacroBodyParenChecker"), DLoc);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMacroBodyParenChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MacroBodyParenChecker>();
}

bool ento::shouldRegisterMacroBodyParenChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MacroBodyParenChecker>("anzu.MacroBodyParenChecker", "Macro body need use paren", "");
}

#endif