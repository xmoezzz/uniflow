#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class DisableCallCStyleStreamChecker : public Checker<check::PreStmt<CallExpr>> {
	public:
		mutable std::unique_ptr<BuiltinBug> BT;

		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void DisableCallCStyleStreamChecker::checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
		const FunctionDecl* FD = C.getCalleeDecl(CE);
		if (!FD)
			return;

		if (!FD->isGlobal())
			return;

		auto Name = FD->getQualifiedNameAsString();
		if (Name == "fprintf" || Name == "printf" || Name == "fscanf" || Name == "scanf") {
			auto FilePath = C.getSourceManager().getFilename(CE->getBeginLoc());
			auto FileName = llvm::sys::path::filename(FilePath);
			auto ExtName = llvm::sys::path::extension(FileName);
			if (ExtName != ".cpp")
				return;

			reportBug(CE->getDirectCallee(), CE->getBeginLoc(), C.getBugReporter());
		}
	}

	void DisableCallCStyleStreamChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "DisableCallCStyleStreamChecker"));
		}

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::DisableCallCStyleStreamChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "DisableCallCStyleStreamChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDisableCallCStyleStreamChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<DisableCallCStyleStreamChecker>();
	}

bool ento::shouldRegisterDisableCallCStyleStreamChecker(const CheckerManager& mgr) {
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
	registry.addChecker<DisableCallCStyleStreamChecker>("anzu.DisableCallCStyleStreamChecker", "", "");
}

#endif