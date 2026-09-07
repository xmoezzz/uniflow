#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class SignedBitFieldWidthChecker : public Checker<check::ASTDecl<RecordDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const RecordDecl* RD, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void SignedBitFieldWidthChecker::checkASTDecl(const RecordDecl* RD, AnalysisManager& Mgr, BugReporter& BR) const {
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::SignedBitFieldWidthChecker, lang);
	for (const auto* F : RD->fields()) {
		if (F->isBitField() && F->getType()->isSignedIntegerType()) {
			if (const Expr* BitWidthExpr = F->getBitWidth()) {
				clang::Expr::EvalResult Result;
				if (BitWidthExpr->EvaluateAsInt(Result, Mgr.getASTContext()) && Result.Val.getInt() <= 1) {
					reportBug(findFunctionDecl(RD), Msg, F->getBeginLoc(), BR);
				}
			}
		}
	}
}

void SignedBitFieldWidthChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "SignedBitFieldWidthChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "SignedBitFieldWidthChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSignedBitFieldWidthChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SignedBitFieldWidthChecker>();
}

bool ento::shouldRegisterSignedBitFieldWidthChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SignedBitFieldWidthChecker>("anzu.SignedBitFieldWidthChecker", "Signed integer variables defined with bit-fields must have a bit-width greater than 1.", "");
}

#endif
