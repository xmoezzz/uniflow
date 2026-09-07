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

	class FormatStringChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void FormatStringChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (const auto* CE = dyn_cast_or_null<CallExpr>(Call.getOriginExpr())) {
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
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string fmt = ls->parseMsgs(anzulocalization::FormatStringChecker, lang);
			// 遍历格式字符串检查非法格式符
			for (size_t i = 0; i < Str.size(); i++) {
				if (Str[i] == '%' && i + 1 < Str.size()) {
					char nextChar = Str[i + 1];
					if (nextChar != 'd' && nextChar != 'i' && nextChar != 'o' && nextChar != 'u' &&
						nextChar != 'x' && nextChar != 'X' && nextChar != 'f' && nextChar != 'F' &&
						nextChar != 'e' && nextChar != 'E' && nextChar != 'g' && nextChar != 'G' &&
						nextChar != 'a' && nextChar != 'A' && nextChar != 'c' && nextChar != 's' &&
						nextChar != 'p' && nextChar != 'n' && nextChar != 'C' && nextChar != 'S' &&
						nextChar != '%') {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}
						std::string Msg = std::vformat(fmt, std::make_format_args(nextChar));
						reportBug(FD, Msg, StrLit->getBeginLoc(), C.getBugReporter());
					}
					i++; // 跳过格式符
				}
			}
		}
	}
}

void FormatStringChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "FormatStringChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "FormatStringChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFormatStringChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FormatStringChecker>();
}

bool ento::shouldRegisterFormatStringChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FormatStringChecker>("anzu.FormatStringChecker", "Checks for illegal format specifiers", "");
}

#endif