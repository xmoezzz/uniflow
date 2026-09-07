#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class MacroParamParenChecker : public Checker<check::EndOfTranslationUnit> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
			AnalysisManager& Mgr,
			BugReporter& BR) const {

			Preprocessor& PP = Mgr.getPreprocessor();
			for (auto it = PP.macro_begin(); it != PP.macro_end(); ++it) {
				if (auto II = it->first) {
					if (MacroInfo* MI = PP.getMacroInfo(II)) {
						checkMacroInfo(Mgr, BR, MI);
					}
				}
			}
		}

		bool checkMacroInfo(AnalysisManager& Mgr, BugReporter& BR, MacroInfo* MI) const {
			if (!MI)
				return true;

			if (0 == MI->getNumParams())
				return true;

			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::MacroParamParenChecker, lang);
			SourceManager& SM = Mgr.getSourceManager();
			for (auto CurToken = MI->tokens_begin(); CurToken != MI->tokens_end(); ++CurToken) {
				if (CurToken->isAnyIdentifier()) {
					if (SM.isInSystemMacro(CurToken->getLocation()) ||
						SM.isInSystemHeader(CurToken->getLocation())) {
						continue;
					}

					bool IsParam = false;
					for (auto Param : MI->params()) {
						if (Param == CurToken->getIdentifierInfo()) {
							IsParam = true;
							break;
						}
					}
					if (!IsParam)
						continue;

					if (!checkMacroParamHasParen(MI, CurToken)) {
						if (!BT) {
							BT.reset(new BuiltinBug(
								this, "MacroParamParenChecker"));
						}

						// Report the issue        
						PathDiagnosticLocation Loc(CurToken->getLocation(), BR.getSourceManager());
						auto Report = std::make_unique<BasicBugReport>(
							*BT, Msg, createRuleExtData(1, "MacroParamParenChecker"), Loc);
						BR.emitReport(std::move(Report));
						return false;
					}
				}
			}

			return true;
		}

		bool checkMacroParamHasParen(MacroInfo* MI, MacroInfo::const_tokens_iterator ParamToken) const {
			auto BeginToken = MI->tokens_begin();
			auto EndToken = MI->tokens_end();
			auto PreToken = ParamToken;
			auto NextToken = ParamToken;
			--PreToken;
			++NextToken;

			//auto Name = ParamToken->getName();
			//auto PreName = PreToken->getName();
			//auto NextName = NextToken->getName();

			if (ParamToken != BeginToken) {
				if (PreToken->getKind() == tok::hash ||
					PreToken->getKind() == tok::hashhash) {
					return true;
				}
			}

			if (ParamToken != EndToken && NextToken != EndToken) {
				if (NextToken->getKind() == tok::hash ||
					NextToken->getKind() == tok::hashhash) {
					return true;
				}
			}

			if (ParamToken == BeginToken || ParamToken == EndToken || NextToken == EndToken) {
				return false;
			}

			if (PreToken->getKind() != tok::l_paren ||
				NextToken->getKind() != tok::r_paren) {
				return false;
			}

			return true;
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMacroParamParenChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MacroParamParenChecker>();
}

bool ento::shouldRegisterMacroParamParenChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MacroParamParenChecker>("anzu.MacroParamParenChecker", "", "");
}

#endif