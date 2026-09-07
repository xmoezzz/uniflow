#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class PrivateStaticMemberChecker : public Checker<check::ASTDecl<CXXRecordDecl>> {
	public:
		mutable std::unique_ptr<BuiltinBug> BT;

		void checkASTDecl(const CXXRecordDecl* RD, AnalysisManager& mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;

	};

	void PrivateStaticMemberChecker::checkASTDecl(const CXXRecordDecl* RD, AnalysisManager& mgr, BugReporter& BR) const {
		if (!RD)
			return;

		if (!RD->hasDefinition())
			return;

		for (auto FD : RD->decls()) {
			const VarDecl* Var = llvm::dyn_cast_or_null<VarDecl>(FD);
			if (!Var) continue;
			if (Var->isStaticDataMember() && FD->getAccess() == AS_private) {
				reportBug(RD, Var->getBeginLoc(), BR);
			}
		}
	}

	void PrivateStaticMemberChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "PrivateStaticMemberChecker"));

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::PrivateStaticMemberChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "PrivateStaticMemberChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPrivateStaticMemberChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PrivateStaticMemberChecker>();
}

bool ento::shouldRegisterPrivateStaticMemberChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::CPP);
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
	registry.addChecker<PrivateStaticMemberChecker>("anzu.PrivateStaticMemberChecker", "", "");
}

#endif
