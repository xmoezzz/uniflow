#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class LongLongTypeChecker : public Checker<check::ASTDecl<VarDecl>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			QualType T = D->getType();
			if (const BuiltinType* BT = T->getAs<BuiltinType>()) {
				if (BT->getKind() == BuiltinType::LongLong) {
					reportBug(findFunctionDecl(D), D->getLocation(), BR);
				}
			}
		}
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "LongLongTypeChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::LongLongTypeChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg,
				createRuleExtData(1, "LongLongTypeChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerLongLongTypeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<LongLongTypeChecker>();
}

bool ento::shouldRegisterLongLongTypeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<LongLongTypeChecker>("anzu.LongLongTypeChecker", "Warns on 'long long' type usage", "");
}

#endif