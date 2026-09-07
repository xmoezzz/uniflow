#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
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

	class PrintFunctionArgCountChecker : public Checker<check::PreStmt<CallExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
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

			const StringLiteral* StrLit = llvm::dyn_cast_or_null<StringLiteral>(FormatArg->IgnoreParenCasts());
			if (!StrLit)
				return;

			StringRef FormatString = StrLit->getString();
			size_t pos = 0;
			unsigned countFormatSpecifiers = 0;
			while ((pos = FormatString.find('%', pos)) != StringRef::npos && pos + 1 < FormatString.size()) {
				if (FormatString[pos + 1] != '%') {
					++countFormatSpecifiers;
				}
				else {
					++pos; // Skip double %%
				}
				++pos;
			}

			unsigned countArguments = CE->getNumArgs() - (It->second + 1);
			if (countFormatSpecifiers > countArguments) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::HardcodedCryptoKeyChecker, lang);
				reportBug(FD, Msg, FormatArg->getBeginLoc(), C.getBugReporter());
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "PrintFunctionArgCountChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "PrintFunctionArgCountChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}

	};
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPrintFunctionArgCountChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PrintFunctionArgCountChecker>();
}

bool ento::shouldRegisterPrintFunctionArgCountChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PrintFunctionArgCountChecker>("anzu.PrintFunctionArgCountChecker", "", "");
}

#endif