#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class ShiftOnCharOrShortChecker : public Checker<check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;

	private:
		bool IsCharOrShortType(const Expr* E, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void ShiftOnCharOrShortChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (B->isShiftOp()) {
		if (IsCharOrShortType(B->getLHS(), C)) {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::ShiftOnCharOrShortChecker, lang);
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, Msg, B->getLHS()->getBeginLoc(), C.getBugReporter());
		}
	}
}

bool ShiftOnCharOrShortChecker::IsCharOrShortType(const Expr* E, CheckerContext& C) const {
	if (!E)
		return false;

	E = E->IgnoreParenImpCasts();
	if (isa<ExplicitCastExpr>(E))
		return false;

	auto Size = C.getASTContext().getTypeSize(E->getType());
	if (Size < 32) {
		return true;
	}

	if (auto UO = dyn_cast<UnaryOperator>(E)) {
		if (UO->getOpcode() == UnaryOperator::Opcode::UO_Not) {
			return IsCharOrShortType(UO->getSubExpr(), C);
		}
	}

	return false;
}

void ShiftOnCharOrShortChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "ShiftOnCharOrShortChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ShiftOnCharOrShortChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerShiftOnCharOrShortChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ShiftOnCharOrShortChecker>();
}

bool ento::shouldRegisterShiftOnCharOrShortChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ShiftOnCharOrShortChecker>("anzu1.ShiftOnCharOrShortChecker", "Beware of integer promotion when performing bitwise operations on integer types smaller than int", "");
}

#endif