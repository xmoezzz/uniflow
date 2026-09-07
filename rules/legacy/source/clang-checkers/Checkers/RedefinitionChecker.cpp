#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class RedefinitionChecker : public Checker<check::ASTDecl<VarDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void RedefinitionChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!VD->isLocalVarDecl() || VD->isStaticLocal() || VD->isExternC()) return;

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::RedefinitionChecker, lang);
	if (const DeclContext* DC = VD->getDeclContext()) {
		if (DC->isFunctionOrMethod()) {
			for (const auto* InnerDecl : DC->decls()) {
				if (const auto* InnerVD = llvm::dyn_cast_or_null<VarDecl>(InnerDecl)) {
					if (VD != InnerVD && InnerVD->getName() == VD->getName()) {
						reportBug(findFunctionDecl(VD), Msg, VD->getBeginLoc(), BR);
						return;
					}
				}
			}
		}
	}
}

void RedefinitionChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "RedefinitionChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "RedefinitionChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerRedefinitionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<RedefinitionChecker>();
}

bool ento::shouldRegisterRedefinitionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<RedefinitionChecker>("anzu.RedefinitionChecker", "Prohibit variable redefinition in inner blocks", "");
}

#endif