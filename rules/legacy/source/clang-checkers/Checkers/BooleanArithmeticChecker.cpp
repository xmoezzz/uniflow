#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

namespace clang {
	namespace ento {

		class BooleanArithmeticChecker : public Checker<check::PreStmt<BinaryOperator>> {
			mutable std::unique_ptr<BuiltinBug> BT;

		public:
			void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
			void checkPreStmt(const UnaryOperator* U, CheckerContext& C) const;
			void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
		};

		void BooleanArithmeticChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
			if (B->isAdditiveOp() || B->isMultiplicativeOp() || B->isShiftOp()) {
				const Expr* BoolExpr = nullptr;
				if (B->getLHS()->IgnoreParenImpCasts()->getType()->isBooleanType()) {
					BoolExpr = B->getLHS();
				}
				else if (B->getRHS()->IgnoreParenImpCasts()->getType()->isBooleanType()) {
					BoolExpr = B->getRHS();
				}

				if (BoolExpr) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}
					auto ls = anzulocalization::LocaleSetting::getInstance();
					uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
					std::string Msg = ls->parseMsgs(anzulocalization::BooleanArithmeticChecker, lang);    
					reportBug(FD, Msg, BoolExpr->getBeginLoc(), C.getBugReporter());
				}
			}
		}

		void BooleanArithmeticChecker::checkPreStmt(const UnaryOperator* U, CheckerContext& C) const {
			if (U->isIncrementDecrementOp() && U->getSubExpr()->IgnoreParenImpCasts()->getType()->isBooleanType()) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::BooleanArithmeticChecker, lang);   
				reportBug(FD, Msg, U->getSubExpr()->getBeginLoc(), C.getBugReporter());
			}
		}

		void BooleanArithmeticChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "BooleanArithmeticChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "BooleanArithmeticChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	} // namespace ento
} // namespace clang

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBooleanArithmeticChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BooleanArithmeticChecker>();
}

bool ento::shouldRegisterBooleanArithmeticChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BooleanArithmeticChecker>("anzu.BooleanArithmeticChecker", "", "");
}

#endif
