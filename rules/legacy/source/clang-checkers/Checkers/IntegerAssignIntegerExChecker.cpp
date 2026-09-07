#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/CheckerManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"
#include <unordered_map>

using namespace clang;
using namespace ento;

namespace {
	class FindBinaryExprVisitor
		: public RecursiveASTVisitor<FindBinaryExprVisitor> {
		std::unordered_map<const Expr*, bool> ExprList;

	public:
		const std::unordered_map<const Expr*, bool>& getExprs() {
			return ExprList;
		}

	private:
		void AddExpr(const Expr* E, bool Explicit) {
			if (auto CE = dyn_cast<CastExpr>(E->IgnoreParens())) {
				auto SE = CE->getSubExpr();
				auto ST = SE->getType();
				auto DT = CE->getType();
				if (ST->isIntegerType() && DT->isIntegerType()) {
					ExprList[E] = Explicit;
				}
				AddExpr(SE, Explicit);
			}
		}

	public:
		bool VisitVarDecl(const VarDecl* VD) {
			if (auto Init = VD->getInit()) {
				if (isa<ExplicitCastExpr>(Init->IgnoreParenImpCasts())) {
					AddExpr(Init, true);
				}
				else{
					AddExpr(Init, false);
				}
			}

			return true;
		}

		bool VisitBinaryOperator(const BinaryOperator* BO) {
			if (BO->getOpcode() == BO_Assign) {
				if (auto RHS = BO->getRHS()) {
					if (isa<ExplicitCastExpr>(RHS->IgnoreParenImpCasts())) {
						AddExpr(RHS, true);
					}
					else {
						AddExpr(RHS, false);
					}
				}
			}
			return true;
		}
	};

	class IntegerAssignIntegerExChecker : public Checker< check::ASTCodeBody, check::PreStmt<CastExpr> > {
		mutable std::unique_ptr<BuiltinBug> BT;
		mutable std::unordered_map<const Expr*, bool> ExprSet;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void checkPreStmt(const CastExpr* CE, CheckerContext& C) const;
		bool checkExpr(const QualType& LT, const QualType& RT, const Expr* RE, CheckerContext& C) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, const std::string& RuleID, BugReporter& BR) const;
	};
}

void IntegerAssignIntegerExChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const
{
	FindBinaryExprVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Exprs = Visitor.getExprs();
	ExprSet.insert(Exprs.begin(), Exprs.end());
}

void IntegerAssignIntegerExChecker::checkPreStmt(const CastExpr* CE, CheckerContext& C) const {
	auto It = ExprSet.find(CE);
	if (It == ExprSet.end())
		return;

	auto SE = CE->getSubExpr();
	auto DE = CE;
	//if (IsConstantExpr(SE))
	//    return;

	if (!checkExpr(DE->getType(), SE->getType(), SE, C))
		return;

	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}

	if (!It->second) {
		reportBug(FD, SE->getBeginLoc(), "IntegerAssignIntegerExChecker.1", C.getBugReporter());
	}
	else {
		reportBug(FD, SE->getBeginLoc(), "IntegerAssignIntegerExChecker.2", C.getBugReporter());
	}
}

bool IntegerAssignIntegerExChecker::checkExpr(const QualType& LT, const QualType& RT, const Expr* RE, CheckerContext& C) const {
	if (!LT->isIntegerType())
		return false;

	if (!RT->isIntegerType())
		return false;

	auto DstBitSize = C.getASTContext().getTypeSize(LT);
	auto SrcBitSize = C.getASTContext().getTypeSize(RT);
	if (DstBitSize >= SrcBitSize)
		return false;

	auto SrcIsUnsigned = RT->isUnsignedIntegerType();
	auto NL = C.getSVal(RE).getAs<NonLoc>();
	if (!NL)
		return false;

	llvm::APInt MinValue;
	llvm::APInt MaxValue;
	if (SrcIsUnsigned) {
		MinValue = llvm::APInt::getMinValue(DstBitSize);
		MaxValue = llvm::APInt::getMaxValue(DstBitSize);
		MinValue = llvm::APInt(SrcBitSize, MinValue.getZExtValue(), false);
		MaxValue = llvm::APInt(SrcBitSize, MaxValue.getZExtValue(), false);
	}
	else {
		MinValue = llvm::APInt::getSignedMinValue(DstBitSize);
		MaxValue = llvm::APInt::getSignedMaxValue(DstBitSize);
		MinValue = llvm::APInt(SrcBitSize, MinValue.getSExtValue(), true);
		MaxValue = llvm::APInt(SrcBitSize, MaxValue.getSExtValue(), true);
	}

	llvm::APSInt MinSValue(MinValue, SrcIsUnsigned);
	llvm::APSInt MaxSValue(MaxValue, SrcIsUnsigned);

	ProgramStateRef stateTrue, stateFalse;
	std::tie(stateTrue, stateFalse) = C.getConstraintManager().assumeInclusiveRangeDual(C.getState(), *NL, MinSValue, MaxSValue);
	if (stateTrue && !stateFalse)
		return false;

	return true;
}

void IntegerAssignIntegerExChecker::reportBug(const Decl* FD, const SourceLocation& Loc, const std::string& RuleID, BugReporter& BR) const {
	if (Loc.isMacroID())
        return;

	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "IntegerAssignIntegerExChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::IntegerAssignIntegerExChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, RuleID), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerIntegerAssignIntegerExChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<IntegerAssignIntegerExChecker>();
}

bool ento::shouldRegisterIntegerAssignIntegerExChecker(const CheckerManager& mgr) {
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
	registry.addChecker<IntegerAssignIntegerExChecker>("anzu1.IntegerAssignIntegerExChecker", "Assigned value is too large integer for the variable", "");
}

#endif