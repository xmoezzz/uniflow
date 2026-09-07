#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/DeclCXX.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindTryCatchVisitor
		: public RecursiveASTVisitor<FindTryCatchVisitor> {
		bool UseExcept = false;

	public:
		bool IsUseExcept() const {
			return UseExcept;
		}

	public:
		bool VisitCXXTryStmt(const CXXTryStmt* TS) {
			UseExcept = true;
			return false;
		}

		bool VisitCXXThrowExpr(const CXXThrowExpr* TE) {
			UseExcept = true;
			return false;
		}
	};

	class SignalHandlerChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;

	private:
		bool isUseTryCatch(const FunctionDecl* FD) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
} // end of anonymous namespace

void SignalHandlerChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(Call.getDecl());
	if (!FD)
		return;

	if (Call.getNumArgs() <= 1)
		return;

	auto FuncName = FD->getNameAsString();
	if (FuncName == "signal" || FuncName == "sigaction") {
		const Expr* HandlerExpr = Call.getArgExpr(1);
		if (!HandlerExpr) return;
		if (const DeclRefExpr* DRE = dyn_cast_or_null<DeclRefExpr>(HandlerExpr->IgnoreParenCasts())) {
			if (const FunctionDecl* HandlerDecl = llvm::dyn_cast_or_null<FunctionDecl>(DRE->getDecl())) {
				if (!HandlerDecl->isExternC() || isUseTryCatch(HandlerDecl)) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}

					reportBug(FD, HandlerExpr->getBeginLoc(), C.getBugReporter());
				}
			}
		}
	}
}

bool SignalHandlerChecker::isUseTryCatch(const FunctionDecl* FD) const {
	if (!FD)
		return false;

	FindTryCatchVisitor Visitor;
	Visitor.TraverseDecl(const_cast<FunctionDecl*>(FD));

	return Visitor.IsUseExcept();
}

void SignalHandlerChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "SignalHandlerChecker"));

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::SignalHandlerChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "SignalHandlerChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSignalHandlerChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SignalHandlerChecker>();
}

bool ento::shouldRegisterSignalHandlerChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SignalHandlerChecker>("anzu.SignalHandlerChecker", "", "");
}

#endif