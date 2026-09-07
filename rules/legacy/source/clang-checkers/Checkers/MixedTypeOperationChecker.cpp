#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class MixedTypeOperationChecker : public Checker<check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
		bool IsConstantExpr(const Expr* E) const;
	};
}

void MixedTypeOperationChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (!B->isAdditiveOp() && !B->isMultiplicativeOp())
		return;

	if (IsConstantExpr(B->getLHS()) || IsConstantExpr(B->getRHS()))
		return;

	QualType LhsType = B->getLHS()->IgnoreParenImpCasts()->getType();
	QualType RhsType = B->getRHS()->IgnoreParenImpCasts()->getType();

	// If the types of the operands are different, report a warning.
	if (!C.getASTContext().hasSameType(LhsType, RhsType)) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}

		reportBug(FD, B->getOperatorLoc(), C.getBugReporter());
	}
}

bool MixedTypeOperationChecker::IsConstantExpr(const Expr* E) const {
	if (!E) return false;
	E = E->IgnoreParenCasts();
	if (isa<IntegerLiteral>(E) ||
		isa<FixedPointLiteral>(E) ||
		isa<CharacterLiteral>(E) ||
		isa<FloatingLiteral>(E) ||
		isa<ImaginaryLiteral>(E) ||
		isa<StringLiteral>(E) ||
		isa<CXXBoolLiteralExpr>(E)) {
		return true;
	}

	if (auto DRE = dyn_cast<DeclRefExpr>(E)) {
		if (auto D = DRE->getDecl()) {
			if (isa<EnumConstantDecl>(D)) {
				return true;
			}
		}
	}

	return false;
}

void MixedTypeOperationChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "UnnecessaryCastChecker"));

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::MixedTypeOperationChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "MixedTypeOperationChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}
/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMixedTypeOperationChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MixedTypeOperationChecker>();
}

bool ento::shouldRegisterMixedTypeOperationChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MixedTypeOperationChecker>("anzu.MixedTypeOperationChecker", "", "");
}

#endif