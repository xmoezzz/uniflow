#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Decl.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class CharTypeOperatorChecker : public Checker<check::PreStmt<BinaryOperator>, check::BranchCondition> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const;
		void checkBranchCondition(const Stmt* Condition, CheckerContext& C) const;

	private:
		void checkDRE(const DeclRefExpr* DRE, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}


void CharTypeOperatorChecker::checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const {
	if (BO->isAdditiveOp() || BO->isMultiplicativeOp()) {
		auto LHS = BO->getLHS()->IgnoreParenImpCasts();
		auto RHS = BO->getRHS()->IgnoreParenImpCasts();
		if (auto DRE = dyn_cast<DeclRefExpr>(LHS)) {
			checkDRE(DRE, C);
		}
		if (auto DRE = dyn_cast<DeclRefExpr>(RHS)) {
			checkDRE(DRE, C);
		}
	}
}

void CharTypeOperatorChecker::checkBranchCondition(const Stmt* Condition, CheckerContext& C) const {

}

void CharTypeOperatorChecker::checkDRE(const DeclRefExpr* DRE, CheckerContext& C) const {
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CharTypeOperatorChecker, lang);
	if (auto D = DRE->getDecl()) {
		if (auto VD = dyn_cast<VarDecl>(D)) {
			if (const Type* T = VD->getType().getTypePtr()) {
				if (const auto* BType = dyn_cast<BuiltinType>(T)) {
					if (BType->getKind() == BuiltinType::Char_S) {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}

						reportBug(FD, Msg, DRE->getBeginLoc(), C.getBugReporter());
					}
				}
			}
		}
	}
}

void CharTypeOperatorChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "ArgumentCountChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CharTypeOperatorChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCharTypeOperatorChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CharTypeOperatorChecker>();
}

bool ento::shouldRegisterCharTypeOperatorChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CharTypeOperatorChecker>("anzu.CharTypeOperatorChecker", "Character variables used for numerical calculations must be explicitly defined as signed or unsigned.", "");
}

#endif
