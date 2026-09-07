#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Expr.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class FloatAssignToIntChecker : public Checker<check::ASTDecl<VarDecl>, check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const;
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const std::string& RuleID, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void FloatAssignToIntChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const {
		if (auto Init = VD->getInit()) {
			QualType LHSType = VD->getType();
			QualType RHSType = Init->IgnoreParenImpCasts()->getType();

			if (LHSType->isIntegerType() && RHSType->isFloatingType()) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::FloatAssignToIntChecker, lang); 

				reportBug(findFunctionDecl(VD), Msg, "FloatAssignToIntChecker.1", VD->getBeginLoc(), BR);
			}
		}
	}

	void FloatAssignToIntChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
		if (!B)
			return;

		if (B->getOpcode() != BO_Assign)
			return;

		const Expr* LHS = B->getLHS();
		const Expr* RHS = B->getRHS();

		if (!LHS || !RHS)
			return;

		QualType LHSType = LHS->getType();
		QualType RHSType = RHS->IgnoreParenImpCasts()->getType();

		if (LHSType->isIntegerType() && RHSType->isFloatingType()) {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::FloatAssignToIntChecker, lang); 

			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, Msg, "FloatAssignToIntChecker.2", B->getOperatorLoc(), C.getBugReporter());
		}
	}

	void FloatAssignToIntChecker::reportBug(const Decl* FD, const std::string& Msg, const std::string& RuleID, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "FloatAssignToIntChecker"));

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, RuleID), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
}


/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFloatAssignToIntChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FloatAssignToIntChecker>();
}

bool ento::shouldRegisterFloatAssignToIntChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FloatAssignToIntChecker>("anzu.FloatAssignToIntChecker", "Floating-point constant assigned to integer variable", "");
}

#endif