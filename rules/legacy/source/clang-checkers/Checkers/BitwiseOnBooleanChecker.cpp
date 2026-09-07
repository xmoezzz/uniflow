#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class BitwiseOnBooleanChecker : public Checker<check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void BitwiseOnBooleanChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (B->isBitwiseOp()) { 
		// 检查操作符是否为位操作
		const Expr* LHS = B->getLHS()->IgnoreParenImpCasts();
		const Expr* RHS = B->getRHS()->IgnoreParenImpCasts();

		// 检查左侧和右侧的操作数是否为布尔值
		if ((LHS->getType()->isBooleanType() || RHS->getType()->isBooleanType())) {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::BitwiseOnBoolChecker, lang);

			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, Msg, B->getOperatorLoc(), C.getBugReporter());
		}
	}
}

void BitwiseOnBooleanChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "BitwiseOnBooleanChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "BitwiseOnBooleanChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBitwiseOnBooleanChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BitwiseOnBooleanChecker>();
}

bool ento::shouldRegisterBitwiseOnBooleanChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BitwiseOnBooleanChecker>("anzu.BitwiseOnBooleanChecker", "Checks for bitwise operators used on boolean values", "");
}

#endif