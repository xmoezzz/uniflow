#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Decl.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class CheckMainSignatureChecker : public Checker<check::ASTDecl<FunctionDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void CheckMainSignatureChecker::checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!D->getIdentifier()) return;
	if (D->getName().str() != "main") return;
	if (!D->isMain()) return;
	if (!D->isGlobal()) return;

	const FunctionType* FT = D->getType()->getAs<FunctionType>();
	if (!FT) return;
	const FunctionProtoType* FPT = llvm::dyn_cast_or_null<FunctionProtoType>(FT);
	if (!FPT) return;

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CheckMainSignatureChecker, lang);
	if (D->getReturnType().getUnqualifiedType() != Mgr.getASTContext().IntTy ||
		!(FPT->getNumParams() == 0 ||
			(FPT->getNumParams() == 2 && FPT->getParamType(0) == Mgr.getASTContext().IntTy &&
				FPT->getParamType(1)->isPointerType()))) {
		reportBug(D, Msg, D->getBeginLoc(), BR);
	}
}

void CheckMainSignatureChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "CheckMainSignatureChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CheckMainSignatureChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCheckMainSignatureChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CheckMainSignatureChecker>();
}

bool ento::shouldRegisterCheckMainSignatureChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CheckMainSignatureChecker>("anzu.CheckMainSignatureChecker", "", "");
}

#endif