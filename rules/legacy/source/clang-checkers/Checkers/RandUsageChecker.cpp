#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class RandUsageChecker : public Checker<check::PreStmt<CallExpr>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const std::string& RuleID, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void RandUsageChecker::checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
		const FunctionDecl* FD = C.getCalleeDecl(CE);
		if (!FD)
			return;
		std::string index;
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::RandUsageChecker, lang);
		auto Name = FD->getQualifiedNameAsString();
		// Check if the function being called is std::rand.
		if (Name == "std::rand") {
			index = "1";
		} else if (Name == "rand") {
			index = "2";
		}
		else if (Name == "random") {
			index = "3";
		}
		else if (Name.find("std::mersenne_twister") == 0) {
			index = "4";
		}
		Name = Name +"()";
		std::string Msg = std::vformat(fmt, std::make_format_args(Name));
		reportBug(CE->getDirectCallee(),  Msg, "RandUsageChecker." + index, CE->getBeginLoc(), C.getBugReporter());
	}

	void RandUsageChecker::reportBug(const Decl* FD, const std::string& Msg, const std::string& RuleID, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "RandUsageChecker"));
		}

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, RuleID), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerRandUsageChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<RandUsageChecker>();
}

bool ento::shouldRegisterRandUsageChecker(const CheckerManager& mgr) {
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
	registry.addChecker<RandUsageChecker>("anzu.RandUsageChecker", "", "");
}

#endif