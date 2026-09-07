#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	static const char* Keywords[] = {
		// C keywords (also keywords in C++)
		"auto", "break", "case", "char", "const", "continue", "default", "do",
		"double", "else", "enum", "extern", "float", "for", "goto", "if",
		"inline", "int", "long", "register", "restrict", "return", "short",
		"signed", "sizeof", "static", "struct", "switch", "typedef", "union",
		"unsigned", "void", "volatile", "while",
		// C++-only keywords
		"alignas", "alignof", "and", "and_eq", "asm", "bitand", "bitor",
		"bool", "catch", "class", "compl", "constexpr", "const_cast",
		"delete", "dynamic_cast", "explicit", "export", "false", "friend",
		"mutable", "namespace", "new", "not", "not_eq", "nullptr", "operator",
		"or", "or_eq", "private", "protected", "public", "reinterpret_cast",
		"static_assert", "static_cast", "template", "this", "thread_local",
		"throw", "true", "try", "typeid", "typename", "using", "virtual", "wchar_t",
		"xor", "xor_eq"
	};

	class KeywordRefinedKeywordChecker : public Checker<check::EndOfTranslationUnit> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
			AnalysisManager& Mgr,
			BugReporter& BR) const {

			Preprocessor& PP = Mgr.getPreprocessor();
			for (auto it = PP.macro_begin(); it != PP.macro_end(); ++it) {
				if (auto II = it->first) {
					auto Name = II->getName();
					for (const char* Keyword : Keywords) {
						if (Name.str() == Keyword) {
							if (MacroInfo* MI = PP.getMacroInfo(II)) {
								checkMacroInfo(Mgr, BR, MI);
							}
						}
					}
				}
			}
		}

		bool checkMacroInfo(AnalysisManager& Mgr, BugReporter& BR, MacroInfo* MI) const {
			if (!MI) {
				return true;
			}

			SourceManager& SM = Mgr.getSourceManager();
			auto Loc = MI->getDefinitionLoc();
			if (SM.isInSystemMacro(Loc) ||
				SM.isInSystemHeader(Loc)) {
				return true;
			}

			if (MI->tokens().size() != 1) {
				return true;
			}

			if (auto II = MI->tokens().begin()->getIdentifierInfo()) {
				auto Name = II->getName().str();
				for (const char* Keyword : Keywords) {
					if (Name == Keyword) {
						reportBug(Loc, BR);
						return false;
					}
				}
			}
			
			return true;
		}

		void reportBug(const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "KeywordRefinedKeywordChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::KeywordRefinedKeywordChecker, lang);
	
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "KeywordRefinedKeywordChecker"), DLoc);
			BR.emitReport(std::move(Report));
		}

	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerKeywordRefinedKeywordChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<KeywordRefinedKeywordChecker>();
}

bool ento::shouldRegisterKeywordRefinedKeywordChecker(const CheckerManager& mgr) {
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
	registry.addChecker<KeywordRefinedKeywordChecker>("anzu.KeywordRefinedKeywordChecker", "", "");
}

#endif