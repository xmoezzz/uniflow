#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class UninitializedMemberChecker : public Checker<check::ASTDecl<CXXConstructorDecl>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		UninitializedMemberChecker() {}

		void checkASTDecl(const CXXConstructorDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			if (D->isDefaultConstructor()) return;
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string fmt = ls->parseMsgs(anzulocalization::UninitializedMemberChecker, lang);

			for (const auto* I : D->inits()) {
				if (!I->isWritten() || I->isInClassMemberInitializer()) continue;

				FieldDecl* FD = I->getMember();
				if (!FD) continue;

				if (!I->getInit() && !FD->hasInClassInitializer()) {
					std::string fd = FD->getNameAsString();
					std::string Msg = std::vformat(fmt, std::make_format_args(fd));
					reportBug(D, Msg, I->getSourceLocation(), BR);
				}
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT = std::make_unique<BuiltinBug>(this, "UninitializedMemberChecker");

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "UninitializedMemberChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}

	};
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUninitializedMemberChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UninitializedMemberChecker>();
}

bool ento::shouldRegisterUninitializedMemberChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UninitializedMemberChecker>("anzu1.UninitializedMemberChecker", "Detects uninitialized class members", "");
}

#endif