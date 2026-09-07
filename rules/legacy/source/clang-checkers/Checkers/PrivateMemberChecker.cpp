#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class PrivateMemberChecker : public Checker<check::ASTDecl<FieldDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;
	public:
		void checkASTDecl(const FieldDecl* FD, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace


void PrivateMemberChecker::checkASTDecl(const FieldDecl* FD, AnalysisManager& Mgr, BugReporter& BR) const {
	auto RD = FD->getParent();
	if (!RD)
		return;

	if (!RD->isClass())
		return;

	// Check if the field is not private
	if (FD->getAccess() != AS_private) {
		PathDiagnosticLocation DLoc = PathDiagnosticLocation::createBegin(FD, BR.getSourceManager());
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::PrivateMemberChecker, lang);
		std::string fd = FD->getNameAsString();
		std::string Message = std::vformat(fmt, std::make_format_args(fd));

		reportBug(RD, Message, FD->getBeginLoc(), BR);
	}
}

void PrivateMemberChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "PrivateMemberChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "PrivateMemberChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPrivateMemberChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PrivateMemberChecker>();
}

bool ento::shouldRegisterPrivateMemberChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PrivateMemberChecker>("anzu.PrivateMemberChecker", "", "");
}

#endif
