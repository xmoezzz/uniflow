#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/Basic/Builtins.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class VariadicChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BugType> BT;
	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void VariadicChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(Call.getDecl());
	if (!FD)
		return;

	if (!FD->isGlobal())
		return;

	if (FD->getNameAsString() != "va_start")
		return;

	if (Call.getNumArgs() < 2)
		return;
					
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::VariadicChecker, lang);
	const Expr* SecondArg = Call.getArgExpr(1);
	if (!SecondArg) return;

	if (auto DRE = dyn_cast<DeclRefExpr>(SecondArg->IgnoreParenCasts())) {
		if (auto D = DRE->getDecl()) {
			if (auto VD = dyn_cast<VarDecl>(D)) {
				if (VD->getType()->isReferenceType()) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}
					reportBug(FD, Msg, SecondArg->getBeginLoc(), C.getBugReporter());
				}
			}
		}		
	}
	else if (auto RT = SecondArg->getType()->getAs<RecordType>()) {
		if (auto RD = RT->getDecl()) {
			if (auto CXXRD = dyn_cast<CXXRecordDecl>(RD)) {
				if (CXXRD->isTriviallyCopyable()) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}
					reportBug(FD, Msg, SecondArg->getBeginLoc(), C.getBugReporter());
				}
			}
		}
	}
}

void VariadicChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "VariadicChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "VariadicChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerVariadicChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<VariadicChecker>();
}

bool ento::shouldRegisterVariadicChecker(const CheckerManager& mgr) {
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
	registry.addChecker<VariadicChecker>("anzu.VariadicChecker", "", "");
}

#endif