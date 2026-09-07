#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

// 01000010130095
// 01000010130096

namespace {
	class ConfusingNamingChecker : public Checker<check::ASTDecl<VarDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		bool FuzzyMachineString(char confCharA, char confCharB, std::string L, std::string R) const;
		void reportBug(const Decl* FD, const std::string& Msg, const std::string& RuleID, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void ConfusingNamingChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!VD->isLocalVarDecl() && !VD->isExternC())
		return;

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg1 = ls->parseMsgs(anzulocalization::ConfusingNamingChecker, lang, 0);
	std::string Msg2 = ls->parseMsgs(anzulocalization::ConfusingNamingChecker, lang, 1);
	auto FD = findFunctionDecl(VD);
	if (const DeclContext* DC = VD->getDeclContext()) {
		std::string Name = VD->getNameAsString();
		for (const auto* InnerDecl : DC->decls()) {
			if (const auto* InnerVD = llvm::dyn_cast_or_null<VarDecl>(InnerDecl)) {
				if (InnerVD != VD) {
					if (FuzzyMachineString('1', 'l', InnerVD->getNameAsString(), Name)) {
						reportBug(FD, Msg1, createRuleExtData(1, "ConfusingNamingChecker.1"), VD->getBeginLoc(), BR);
					}
					else if (FuzzyMachineString('0', 'O', InnerVD->getNameAsString(), Name)) {
						reportBug(FD, Msg2, createRuleExtData(1, "ConfusingNamingChecker.2"), VD->getBeginLoc(), BR);
					}
				}
			}
		}
	}
}

bool ConfusingNamingChecker::FuzzyMachineString(char confCharA, char confCharB, std::string L, std::string R) const {
	if (L == R)
		return false;

	std::replace(L.begin(), L.end(), confCharA, '*');
	std::replace(L.begin(), L.end(), confCharB, '*');
	std::replace(R.begin(), R.end(), confCharA, '*');
	std::replace(R.begin(), R.end(), confCharB, '*');
	return L == R;
}

void ConfusingNamingChecker::reportBug(const Decl* FD, const std::string& Msg, const std::string& RuleID, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ConfusingNamingChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, RuleID, DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerConfusingNamingChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ConfusingNamingChecker>();
}

bool ento::shouldRegisterConfusingNamingChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ConfusingNamingChecker>("anzu.ConfusingNamingChecker", "Prohibit variables that mix lowercase 'l/O' and digit '1/0'", "");
}

#endif