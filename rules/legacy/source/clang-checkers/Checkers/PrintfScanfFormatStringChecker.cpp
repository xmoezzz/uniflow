#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"
#include <unordered_map>

using namespace clang;
using namespace ento;

namespace {
	std::unordered_map<std::string, int> FormatFunc =
	{
		{"printf", 0},
		{"fprintf", 1},
		{"sprintf", 1},
		{"snprintf", 2},
	};

	class PrintfScanfFormatStringChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void PrintfScanfFormatStringChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	const auto* CE = dyn_cast_or_null<CallExpr>(Call.getOriginExpr());
	if (!CE)
		return;

	const FunctionDecl* FD = C.getCalleeDecl(CE);
	if (!FD || !FD->isExternC())
		return;

	auto FuncName = FD->getNameAsString();
	auto It = FormatFunc.find(FuncName);
	if (It == FormatFunc.end())
		return;

	if (CE->getNumArgs() <= It->second)
		return;

	const Expr* FormatArg = CE->getArg(It->second);
	if (!FormatArg)
		return;

	// 检查该表达式是否为字符串字面量
	if (!isa<StringLiteral>(FormatArg->IgnoreParenCasts())) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::PrintfScanfFormatStringChecker, lang);
		reportBug(FD, Msg, FormatArg->getBeginLoc(), C.getBugReporter());
	}
}

void PrintfScanfFormatStringChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
			
	if (!BT)
		BT.reset(new BuiltinBug(this, "PrintfScanfFormatStringChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "PrintfScanfFormatStringChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPrintfScanfFormatStringChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PrintfScanfFormatStringChecker>();
}

bool ento::shouldRegisterPrintfScanfFormatStringChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PrintfScanfFormatStringChecker>("anzu.PrintfScanfFormatStringChecker", "Checks that the format string in printf/scanf is a string literal", "");
}

#endif