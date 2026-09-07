#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class ArgumentCountChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
} // end anonymous namespace

void ArgumentCountChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (C.getASTContext().HasSyntaxErrors()) {
		return;
	}

	if (!Call.getDecl()) return;
	const FunctionDecl* FD = dyn_cast<FunctionDecl>(Call.getDecl());
	if (!FD) return;

	// 如果是变参函数，我们不进行检查
	if (FD->isVariadic()) return;
	if (isa<CXXConstructorDecl>(FD)) return;

	unsigned NumActualArgs = Call.getNumArgs();
	unsigned NumFormalArgs = FD->getNumParams();

	unsigned NumActualArgsReal = 0;
	SourceLocation EndLoc;
	for (unsigned i = 0; i < NumActualArgs; ++i)
	{
		const Expr* Arg = Call.getArgExpr(i);
		if (!Arg) return;
		if (Arg && Arg->isDefaultArgument())
		{
			continue;
		}
		EndLoc = Arg->getEndLoc();
		++NumActualArgsReal;
	}

	// 检查实参和形参的个数是否匹配
	if (NumActualArgsReal != NumFormalArgs) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::ArgumentCountChecker, lang);

		std::string Msg = std::vformat(fmt, std::make_format_args(NumFormalArgs, NumActualArgsReal));
		reportBug(FD, Msg, EndLoc, C.getBugReporter());
	}
}

void ArgumentCountChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {	
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "ArgumentCountChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ArgumentCountChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerArgumentCountChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ArgumentCountChecker>();
}

bool ento::shouldRegisterArgumentCountChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ArgumentCountChecker>("anzu.ArgumentCountChecker", "Checks argument count in function calls", "");
}

#endif