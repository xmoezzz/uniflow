#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class MacroBodyMultStmtChecker : public Checker<check::EndOfTranslationUnit> {
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
			bool HasSemi = false;
			bool HasWhile = false;
			bool CheckSemi = false;
			for (auto token : MI->tokens()) {
				if (!CheckSemi && HasSemi) {
					CheckSemi = true;
				}

				if (token.getKind() == tok::semi) {
					HasSemi = true;
				}

				if (token.getKind() == tok::kw_do) {
					HasWhile = true;
				}

				if (token.getKind() == tok::kw_while) {
					HasWhile = true;
				}

				if (token.getKind() == tok::kw_for) {
					HasWhile = true;
				}

				if (token.getKind() == tok::kw_switch) {
					HasWhile = true;
				}

				if (token.getKind() == tok::kw_case) {
					HasWhile = true;
				}

				if (token.getKind() == tok::kw_if) {
					HasWhile = true;
				}

				if (token.getKind() == tok::kw_virtual) {
					HasWhile = true;
				}

				if (token.getKind() == tok::l_brace) {
					HasWhile = true;
				}

				if (HasWhile) {
					break;
				}
			}
			if (HasWhile) {
				return true;
			}

			if (!CheckSemi) {
				return true;
			}

			return false;
		}

		void reportBug(const SourceLocation& Loc, BugReporter& BR) const {
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "MacroBodyMultStmtChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::MacroBodyMultStmtChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "MacroBodyMultStmtChecker"), DLoc);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMacroBodyMultStmtChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MacroBodyMultStmtChecker>();
}

bool ento::shouldRegisterMacroBodyMultStmtChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MacroBodyMultStmtChecker>("anzu.MacroBodyMultStmtChecker", "", "");
}

#endif