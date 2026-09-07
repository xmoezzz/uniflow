#include "CheckerHandlerRegistry.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <list>
#include <unordered_set>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
    class RedefinedMacroCheckerHandler : public checker::PreprocessorHandler {
    private:
        static std::unordered_set<std::string> Macros;
        static std::list<SourceLocation> Paths;

    private:
        virtual void MacroDefined(Preprocessor& PP, const Token& MacroNameTok,
            const MacroDirective* MD) override {
            if (auto II = MacroNameTok.getIdentifierInfo()) {
                auto MacroName = II->getName().str();
                if (Macros.find(MacroName) != Macros.end()) {
                    Paths.push_back(MacroNameTok.getLocation());
                }
                Macros.insert(MacroName);
            }
        }

        virtual void MacroUndefined(Preprocessor& PP, const Token& MacroNameTok,
            const MacroDefinition& MD,
            const MacroDirective* Undef) override {
            if (auto II = MacroNameTok.getIdentifierInfo()) {
                auto MacroName = II->getName().str();
                auto it = Macros.find(MacroName);
                if (it != Macros.end()) {
                    Macros.erase(it);
                }
            }
        }

    public:
        static const std::list<SourceLocation>& GetPaths() {
            return Paths;
        }
    };
    std::unordered_set<std::string> RedefinedMacroCheckerHandler::Macros;
    std::list<SourceLocation> RedefinedMacroCheckerHandler::Paths;

    static checker::PreprocessorHandlerRegistry::Add<RedefinedMacroCheckerHandler>
        Handler("RedefinedMacroChecker", "RedefinedMacroChecker");

    class RedefinedMacroChecker : public Checker<check::EndOfTranslationUnit> {
        mutable std::unique_ptr<BuiltinBug> BT;

    public:
        void checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
            AnalysisManager& Mgr, BugReporter& BR) const {
            auto& SM = Mgr.getSourceManager();
            auto& Paths = RedefinedMacroCheckerHandler::GetPaths();
            for (auto& Loc : Paths) {
                if (!SM.isInSystemMacro(Loc) && !SM.isInSystemHeader(Loc)) {
                    auto FileName = SM.getFilename(Loc);
                    if (!FileName.empty()) {
                        reportBug(Loc, BR);
                    }
                }
            }
        }

        void reportBug(const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
            if (!BT) {
                BT.reset(new BuiltinBug(
                    this,
                    "RedefinedMacroChecker"));
            }

            // Report the issue
            auto ls = anzulocalization::LocaleSetting::getInstance();
            uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
            std::string Msg = ls->parseMsgs(anzulocalization::RedefinedMacroChecker, lang);
            PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
            auto Report = std::make_unique<BasicBugReport>(
                *BT,
                Msg,
                createRuleExtData(1, "RedefinedMacroChecker"), DLoc);
            BR.emitReport(std::move(Report));
        }
    };
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerRedefinedMacroChecker(CheckerManager &Mgr) {
  Mgr.registerChecker<RedefinedMacroChecker>();
}

bool ento::shouldRegisterRedefinedMacroChecker(const CheckerManager &mgr) {
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
void clang_registerCheckers(CheckerRegistry &registry) {
  registry.addChecker<RedefinedMacroChecker>("anzu.RedefinedMacroChecker", "Prevent #define from being redefined.", "");
}

#endif