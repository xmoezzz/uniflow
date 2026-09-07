#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class DeprecatedFunctionChecker : public Checker<check::PreStmt<CallExpr>> {
	public:
		mutable std::unique_ptr<BuiltinBug> BT;

		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void DeprecatedFunctionChecker::checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
		const FunctionDecl* FD = C.getCalleeDecl(CE);
		if (!FD)
			return;

		auto PD = FD->getParent();
		if (!PD)
			return;

		auto ND = dyn_cast<NamedDecl>(PD);
		if (!ND)
			return;

		if (ND->getNameAsString() != "std")
			return;

		static const llvm::StringSet<> DeprecatedFunctions = {
			"unary_function", "binary_function", "pointer_to_unary_function",
			"pointer_to_binary_function", "mem_fun_t", "mem_fun1_t",
			"mem_fun", "mem_fun_ref_t", "mem_fun1_ref_t", "mem_fun_ref",
			"binder1st", "binder2nd", "bind1st", "bind2nd", "auto_ptr",
			"unexpected_handler", "set_unexpected", "get_unexpected",
			"unexpected", "random_shuffle"
		};

		if (DeprecatedFunctions.count(FD->getNameAsString())) {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}

			reportBug(FD, CE->getBeginLoc(), C.getBugReporter());
		}
	}

	void DeprecatedFunctionChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "DeprecatedFunctionChecker"));

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::DeprecatedFunctionChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "DeprecatedFunctionChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}


} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDeprecatedFunctionChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<DeprecatedFunctionChecker>();
}

bool ento::shouldRegisterDeprecatedFunctionChecker(const CheckerManager& mgr) {
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
	registry.addChecker<DeprecatedFunctionChecker>("anzu.DeprecatedFunctionChecker", "", "");
}

#endif
