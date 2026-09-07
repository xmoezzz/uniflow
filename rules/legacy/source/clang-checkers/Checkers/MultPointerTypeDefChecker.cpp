#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Decl.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class MultPointerTypeDefChecker : public Checker<check::ASTDecl<VarDecl>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}
void MultPointerTypeDefChecker::checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	if (auto Type = D->getType().getTypePtr()) {
		if (auto PType = dyn_cast<PointerType>(Type)) {
			if (auto CType = PType->getPointeeType().getTypePtr()) {
				if (auto CPType = dyn_cast<PointerType>(CType)) {
					if (CPType->getPointeeType()->isPointerType()) {
						auto ls = anzulocalization::LocaleSetting::getInstance();
						uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
						std::string Msg = ls->parseMsgs(anzulocalization::MultPointerTypeDefChecker, lang);
						reportBug(findFunctionDecl(D), Msg, D->getBeginLoc(), BR);
					}
				}
			}
		}
	}
}

void MultPointerTypeDefChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "MultPointerTypeDefChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "MultPointerTypeDefChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMultPointerTypeDefChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MultPointerTypeDefChecker>();
}

bool ento::shouldRegisterMultPointerTypeDefChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MultPointerTypeDefChecker>("anzu.MultPointerTypeDefChecker", "Prohibit pointers to pointers beyond two levels", "");
}

#endif
