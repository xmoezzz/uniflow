#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"
#include <unordered_map>
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {
	enum BO_OP {
		BO_OP_SHIFT = 1,
		BO_OP_ARITH = 2,
	};

	struct BO_DECL {
		const VarDecl* VD;
		BO_OP OP;
	};

	class MixedBitwiseAndArithmeticChecker : public Checker<check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;
		mutable std::unordered_set<const VarDecl*> IgnoreVDs;

	public:
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		void containShiftAndArithOp(const BinaryOperator* B, std::unordered_map<const VarDecl*, int>& OPS) const;
		void setOp(std::unordered_map<const VarDecl*, int>& OPS, const Expr* E, BO_OP OP) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void MixedBitwiseAndArithmeticChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	auto str = ToString(B);
	std::unordered_map<const VarDecl*, int> OPS;
	containShiftAndArithOp(B, OPS);
	for (auto& OP : OPS) {
		if ((OP.second & BO_OP_SHIFT) && (OP.second & BO_OP_ARITH)) {
			IgnoreVDs.insert(OP.first);
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, B->getBeginLoc(), C.getBugReporter());
		}
	}	
}

void MixedBitwiseAndArithmeticChecker::containShiftAndArithOp(const BinaryOperator* B, std::unordered_map<const VarDecl*, int>& OPS) const {
	if (!B)
		return;

	auto LHS = B->getLHS()->IgnoreParenCasts();
	auto RHS = B->getRHS()->IgnoreParenCasts();
	if (B->isShiftOp() || B->isShiftAssignOp()) {
		setOp(OPS, LHS, BO_OP_SHIFT);
	}

	if (B->isAdditiveOp() || B->isMultiplicativeOp()) {
		setOp(OPS, LHS, BO_OP_ARITH);
		setOp(OPS, RHS, BO_OP_ARITH);
	}

	if (B->getOpcode() == BinaryOperatorKind::BO_AddAssign ||
		B->getOpcode() == BinaryOperatorKind::BO_SubAssign || 
		B->getOpcode() == BinaryOperatorKind::BO_MulAssign || 
		B->getOpcode() == BinaryOperatorKind::BO_DivAssign ||
		B->getOpcode() == BinaryOperatorKind::BO_RemAssign) {
		setOp(OPS, LHS, BO_OP_ARITH);
	}

	containShiftAndArithOp(dyn_cast<BinaryOperator>(LHS), OPS);
	containShiftAndArithOp(dyn_cast<BinaryOperator>(RHS), OPS);
}

void MixedBitwiseAndArithmeticChecker::setOp(std::unordered_map<const VarDecl*, int>& OPS, const Expr* E, BO_OP OP) const {
	if (!E)
		return;

	auto DRE = dyn_cast<DeclRefExpr>(E->IgnoreParenCasts());
	if (!DRE)
		return;

	auto D = DRE->getDecl();
	if (!D)
		return;

	auto VD = dyn_cast<VarDecl>(D);
	if (!VD)
		return;

	if (IgnoreVDs.find(VD) != IgnoreVDs.end())
		return;

	auto It = OPS.find(VD);
	if (It == OPS.end()) {
		OPS[VD] = OP;
	}
	else {
		It->second |= OP;
	}
}

void MixedBitwiseAndArithmeticChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "MixedBitwiseAndArithmeticChecker"));

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::MixedBitwiseAndArithmeticChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT,
		Msg,
		createRuleExtData(1, "MixedBitwiseAndArithmeticChecker"),
		DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMixedBitwiseAndArithmeticChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MixedBitwiseAndArithmeticChecker>();
}

bool ento::shouldRegisterMixedBitwiseAndArithmeticChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MixedBitwiseAndArithmeticChecker>("anzu1.MixedBitwiseAndArithmeticChecker", "", "");
}

#endif