#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class MisusedFunctionAddressChecker : public Checker<check::PreStmt<BinaryOperator>, check::BranchCondition> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreStmt(const UnaryOperator* UO, CheckerContext& C) const {
			if (UO->getOpcode() != UnaryOperator::Opcode::UO_LNot)
				return;

			if (isFunctionDeclRef(UO->getSubExpr())) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				reportBug(FD, UO->getSubExpr()->getBeginLoc(), C.getBugReporter());
			}
		}

		void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const {
			if (BO->isAssignmentOp())
				return;

			if (isFunctionDeclRef(BO->getLHS())) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				reportBug(FD, BO->getLHS()->getBeginLoc(), C.getBugReporter());
			}

			if (isFunctionDeclRef(BO->getRHS())) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				reportBug(FD, BO->getRHS()->getBeginLoc(), C.getBugReporter());
			}
		}

		void checkBranchCondition(const Stmt* S, CheckerContext& C) const {
			if (auto E = dyn_cast<Expr>(S)) {
				if (auto UO = dyn_cast<UnaryOperator>(E)) {
					checkPreStmt(UO, C);
				}
				if (auto BO = dyn_cast<BinaryOperator>(E)) {
					checkPreStmt(BO, C);
				}
			}
		}

	private:
		bool isFunctionDeclRef(const Expr* E) const {
			if (!E)
				return false;

			if (auto DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenImpCasts())) {
				if (auto D = DRE->getDecl()) {
					return isa<FunctionDecl>(D);
				}
			}

			return false;
		}

		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "MisusedFunctionAddressChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::MisusedFunctionAddressChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "MisusedFunctionAddressChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}

	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMisusedFunctionAddressChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MisusedFunctionAddressChecker>();
}

bool ento::shouldRegisterMisusedFunctionAddressChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MisusedFunctionAddressChecker>("anzu.MisusedFunctionAddressChecker", "Detects improper usage of function addresses", "");
}

#endif