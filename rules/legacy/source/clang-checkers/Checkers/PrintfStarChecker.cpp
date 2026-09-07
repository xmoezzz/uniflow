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

	class PrintfStarChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void checkStarRealParamType(const CallExpr* CE, int Idx, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& RuleId, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void PrintfStarChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
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

	if (const StringLiteral* StrLit = llvm::dyn_cast_or_null<StringLiteral>(FormatArg->IgnoreParenCasts())) {
		StringRef Str = StrLit->getString();

		// 计算星号'*'的数量，并考虑到"%.*"的情况
		size_t requiredArgs = 0;
		for (size_t i = 0; i < Str.size(); i++) {
			if (Str[i] == '%' && i + 1 < Str.size()) {
				if (Str[i + 1] == '%') {
					i++;
				}
				else if (Str[i + 1] == '*') {
					checkStarRealParamType(CE, It->second + 1 + requiredArgs, C);
					requiredArgs += 2; // 需要一个整数参数和一个被格式化的参数
					i++; // 跳过格式符
				}
				else if (Str[i + 1] == '.' && i + 2 < Str.size() && Str[i + 2] == '*') {
					checkStarRealParamType(CE, It->second + 1 + requiredArgs, C);
					requiredArgs += 2; // "%.*"的情况，同样需要两个参数
					i += 2; // 跳过格式符
				}
				else {
					requiredArgs++; // 普通格式符，需要一个参数
				}
			}
		}

		// 检查是否有足够的参数与星号'*'匹配
		if (requiredArgs > CE->getNumArgs() - It->second - 1) {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::PrintfStarChecker, lang);
			reportBug(FD, "PrintfStarChecker.1", Msg, FormatArg->getBeginLoc(), C.getBugReporter());
		}
	}
}

void PrintfStarChecker::checkStarRealParamType(const CallExpr* CE, int Idx, CheckerContext& C) const {
	if (CE->getNumArgs() <= Idx)
		return;

	auto ArgExpr = CE->getArg(Idx);
	if (!ArgExpr || ArgExpr->getType()->isIntegerType() && IsConstantExpr(ArgExpr))
		return;

	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::PrintfStarChecker, lang);
	reportBug(FD, "PrintfStarChecker.2", Msg, ArgExpr->getBeginLoc(), C.getBugReporter());
}

void PrintfStarChecker::reportBug(const Decl* FD, const std::string& RuleId, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
			
	if (!BT)
		BT.reset(new BuiltinBug(this, "PrintfStarChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, RuleId), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPrintfStarChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PrintfStarChecker>();
}

bool ento::shouldRegisterPrintfStarChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PrintfStarChecker>("anzu.PrintfStarChecker", "Checks for missing arguments for '*' in printf", "");
}

#endif