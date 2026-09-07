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

// 01000010110152
// 01000010110433

namespace {
	class ConfusingNamesChecker : public Checker<check::ASTDecl<VarDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		bool FuzzyMachineString(char confCharA, char confCharB, std::string L, std::string R) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void ConfusingNamesChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr, BugReporter& BR) const {
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::ConfusingNamesChecker, lang);  
	if (const DeclContext* DC = VD->getDeclContext()) {
		std::string Name = VD->getNameAsString();
		for (const auto* InnerDecl : DC->decls()) {
			if (const auto* InnerVD = llvm::dyn_cast_or_null<VarDecl>(InnerDecl)) {
				if (InnerVD != VD) {
					if (FuzzyMachineString('O', '0', InnerVD->getNameAsString(), Name) ||
						FuzzyMachineString('l', '1', InnerVD->getNameAsString(), Name) ||
						FuzzyMachineString('Z', '2', InnerVD->getNameAsString(), Name) ||
						FuzzyMachineString('S', '5', InnerVD->getNameAsString(), Name) ||
						FuzzyMachineString('B', '8', InnerVD->getNameAsString(), Name) ||
						FuzzyMachineString('h', 'n', InnerVD->getNameAsString(), Name) ||
						FuzzyMachineString('m', 'rn', InnerVD->getNameAsString(), Name)) {
						reportBug(findFunctionDecl(VD), Msg, VD->getBeginLoc(), BR);
					}
				}
			}
		}
	}
}

bool ConfusingNamesChecker::FuzzyMachineString(char confCharA, char confCharB, std::string L, std::string R) const {
	if (L == R)
		return false;

	std::replace(L.begin(), L.end(), confCharA, '*');
	std::replace(L.begin(), L.end(), confCharB, '*');
	std::replace(R.begin(), R.end(), confCharA, '*');
	std::replace(R.begin(), R.end(), confCharB, '*');
	return L == R;
}

void ConfusingNamesChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ConfusingNamesChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ConfusingNamesChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerConfusingNamesChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ConfusingNamesChecker>();
}

bool ento::shouldRegisterConfusingNamesChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ConfusingNamesChecker>("anzu.ConfusingNamesChecker", "Check for visually confusing identifiers", "");
}

#endif