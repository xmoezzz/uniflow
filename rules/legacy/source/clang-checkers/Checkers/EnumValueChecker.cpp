#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class EnumValueChecker : public Checker<check::ASTDecl<VarDecl>, check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const;
		void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
} // end anonymous namespace

void EnumValueChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const {
	if (auto Init = VD->getInit()) {
		QualType lhsType = VD->getType();
		QualType rhsType = Init->IgnoreParenImpCasts()->getType();

		if (!lhsType->isEnumeralType() && rhsType->isEnumeralType()) {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::EnumValueChecker, lang);

			reportBug(findFunctionDecl(VD), Msg, VD->getBeginLoc(), BR);
		}
	}
}

void EnumValueChecker::checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const {
	// 只检查赋值操作
	if (BO->getOpcode() != BO_Assign)
		return;

	// 获取左侧和右侧表达式
	const Expr* LHS = BO->getLHS()->IgnoreParenImpCasts();
	const Expr* RHS = BO->getRHS()->IgnoreParenImpCasts();

	QualType lhsType = LHS->getType();
	QualType rhsType = RHS->getType();

	// 检查左侧是否为非枚举类型且右侧是否为枚举类型
	if (!lhsType->isEnumeralType() && rhsType->isEnumeralType()) {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::EnumValueChecker, lang);

		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}
		reportBug(FD, Msg, BO->getOperatorLoc(), C.getBugReporter());
	}
}

void EnumValueChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (Loc.isMacroID())
		return;

	if (!BT)
		BT.reset(new BuiltinBug(this, "EnumValueChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "EnumValueChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerEnumValueChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<EnumValueChecker>();
}

bool ento::shouldRegisterEnumValueChecker(const CheckerManager& mgr) {
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
	registry.addChecker<EnumValueChecker>("anzu.EnumValueChecker", "Checks for non-enum variables assigned enum values", "");
}

#endif