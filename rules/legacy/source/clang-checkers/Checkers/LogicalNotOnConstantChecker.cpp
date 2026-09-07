#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Expr.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class LogicalNotOnConstantChecker
		: public Checker<check::PreStmt<UnaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const UnaryOperator* U, CheckerContext& C) const {
			if (U->getOpcode() != UO_LNot)
				return;

			const Expr* SubExpr = U->getSubExpr();

			llvm::APSInt Result;
			if (SubExpr->isIntegerConstantExpr(C.getASTContext())) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::LogicalNotOnConstantChecker, lang);

				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				reportBug(FD, Msg, U->getOperatorLoc(), C.getBugReporter());
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "LogicalNotOnConstantChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "LogicalNotOnConstantChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerLogicalNotOnConstantChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<LogicalNotOnConstantChecker>();
}

bool ento::shouldRegisterLogicalNotOnConstantChecker(const CheckerManager& mgr) {
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
	registry.addChecker<LogicalNotOnConstantChecker>("anzu.LogicalNotOnConstantChecker", "Disallow logical not operation on constant values", "");
}

#endif