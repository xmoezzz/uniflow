#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Decl.h"
#include "llvm/ADT/SmallSet.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class TypedefRedefinitionChecker : public Checker<check::ASTDecl<TypedefDecl>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTDecl(const TypedefDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void TypedefRedefinitionChecker::checkASTDecl(const TypedefDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	QualType QT = D->getUnderlyingType();
	if (const TypedefType* TDT = QT->getAs<TypedefType>()) {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::TypedefRedefinitionChecker, lang);
		reportBug(findFunctionDecl(D), Msg, D->getBeginLoc(), BR);
	}
}

void TypedefRedefinitionChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "TypedefRedefinitionChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "TypedefRedefinitionChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerTypedefRedefinitionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<TypedefRedefinitionChecker>();
}

bool ento::shouldRegisterTypedefRedefinitionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<TypedefRedefinitionChecker>("anzu.TypedefRedefinitionChecker", "Checks for missing parameter type declarations", "");
}

#endif
