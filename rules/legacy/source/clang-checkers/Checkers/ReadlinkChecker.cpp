#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/DynamicExtent.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {
	taint::TaintTagType READLINK_ID = 0x2000;

	class FindReadlinkVisitor
		: public RecursiveASTVisitor<FindReadlinkVisitor> {
		std::unordered_set<const VarDecl*> VDS;

	public:
		const std::unordered_set<const VarDecl*>& getVDs() {
			return VDS;
		}

	public:
		bool VisitVarDecl(const VarDecl* VD) {
			if (auto Init = VD->getInit()) {
				if (auto CE = dyn_cast<CallExpr>(Init->IgnoreParenCasts())) {
					if (auto FD = CE->getDirectCallee()) {
						if (FD->isGlobal() &&
							FD->getName() == "readlink" &&
							CE->getNumArgs() >= 3) {
							VDS.insert(VD);
						}
					}
				}
			}
			return true;
		}

		bool VisitBinaryOperator(const BinaryOperator* BO) {
			if (auto CE = dyn_cast<CallExpr>(BO->getRHS()->IgnoreParenCasts())) {
				if (auto FD = CE->getDirectCallee()) {
					if (FD->isGlobal() &&
						FD->getName() == "readlink" &&
						CE->getNumArgs() >= 3) {
						if (auto DRE = dyn_cast<DeclRefExpr>(BO->getRHS()->IgnoreParenCasts())) {
							if (auto D = DRE->getDecl()) {
								if (auto VD = dyn_cast<VarDecl>(D)) {
									VDS.insert(VD);
								}
							}
						}
					}
				}
			}
			return true;
		}
	};

	class ReadlinkChecker : public Checker<check::PostCall, check::PreStmt<ArraySubscriptExpr>> {
		mutable std::unique_ptr<BugType> BT;
		mutable FindReadlinkVisitor Visitor;
		mutable std::unordered_set<const FunctionDecl*> FDs;

	public:
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPreStmt(const ArraySubscriptExpr* ASE, CheckerContext& C) const;
		bool checkArraySubscriptExprValid(const ArraySubscriptExpr* ASE, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void ReadlinkChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
	const FunctionDecl* FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
	if (!FD || !FD->isGlobal() || FD->getName() != "readlink" || Call.getNumArgs() < 3)
		return;

	auto MaxExpr = Call.getArgExpr(2);

	clang::Expr::EvalResult Result;
	if (!MaxExpr->EvaluateAsInt(Result, C.getASTContext()))
		return;

	auto MaxValue = Result.Val.getInt();
	if (MaxValue <= 0)
		return;

	MaxValue--;

	auto Val = Call.getReturnValue();
	auto RetVal = Val.getAs<NonLoc>();
	if (!RetVal)
		return;

	auto State = C.getState();
	State = taint::addTaint(State, *RetVal, READLINK_ID);

	auto& CM = State->getConstraintManager();

	llvm::APInt I1(MaxValue.getBitWidth(), -1, false);
	llvm::APSInt N1(I1, true);

	ProgramStateRef stateTrue, stateFalse;
	std::tie(stateTrue, stateFalse) = CM.assumeInclusiveRangeDual(State, *RetVal, N1, N1);
	if (stateTrue) {
		C.addTransition(stateTrue);
	}

	if (stateFalse) {
		llvm::APInt I2(MaxValue.getBitWidth(), 0, MaxValue.isSigned());
		llvm::APSInt N2(I2, !MaxValue.isSigned());
		stateFalse = CM.assumeInclusiveRange(stateFalse, *RetVal, N2, MaxValue, true);
		if (stateFalse) {
			C.addTransition(stateFalse);
		}
	}
}

void ReadlinkChecker::checkPreStmt(const ArraySubscriptExpr* ASE, CheckerContext& C) const {
	if (checkArraySubscriptExprValid(ASE, C))
		return;

	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}

	if (FD && FDs.find(FD) == FDs.end()) {
		FDs.insert(FD);

		Visitor.TraverseDecl(const_cast<FunctionDecl*>(FD));
	}
	auto& VDs = Visitor.getVDs();
	if (auto Idx = ASE->getIdx()) {
		const VarDecl* VD = nullptr;
		if (auto DRE = dyn_cast<DeclRefExpr>(Idx->IgnoreParenCasts())) {
			if (auto D = DRE->getDecl()) {
				VD = dyn_cast<VarDecl>(D);
			}
		}
		auto Val = C.getState()->getSVal(Idx, C.getLocationContext());
		if (taint::isTainted(C.getState(), Val, READLINK_ID) ||
			(VD && VDs.find(VD) != VDs.end())) {
			reportBug(FD, Idx->getBeginLoc(), C.getBugReporter());
		}
	}
}

bool ReadlinkChecker::checkArraySubscriptExprValid(const ArraySubscriptExpr* ASE, CheckerContext& C) const {
	SVal indexVal = C.getSVal(ASE->getIdx());
	SVal arrayVal = C.getSVal(ASE->getBase());

	if (!dyn_cast<NonLoc>(indexVal)) {
		return true;
	}

	Optional<Loc> arrayLoc = arrayVal.getAs<Loc>();
	if (!arrayLoc)
		return true;

	const MemRegion* arrayRegion = arrayLoc->getAsRegion();
	if (!arrayRegion) {
		return true;
	}

	const ElementRegion* ER = llvm::dyn_cast_or_null<ElementRegion>(arrayRegion);
	if (!ER) {
		return true;
	}

	auto SR = ER->getSuperRegion();
	if (!SR) {
		return true;
	}

	auto arraySizeVal = getDynamicElementCount(
		C.getState(), SR, C.getSValBuilder(), ER->getValueType());
	if (!dyn_cast<NonLoc>(arraySizeVal)) {
		return true;
	}

	auto ZeroVal = C.getSValBuilder().makeZeroVal(arraySizeVal.getType(C.getASTContext()));
	auto IsZero = C.getSValBuilder().evalEQ(C.getState(), ZeroVal, arraySizeVal);
	if (!dyn_cast<DefinedSVal>(IsZero)) {
		return true;
	}
	if (C.getState()->assume(IsZero.castAs<DefinedSVal>()).first) {
		return true;
	}

	SVal compareVal = C.getSValBuilder().evalBinOpNN(C.getState(), BO_GE, indexVal.castAs<NonLoc>(), arraySizeVal.castAs<NonLoc>(), C.getSValBuilder().getConditionType());
	if (!dyn_cast<DefinedSVal>(compareVal)) {
		return true;
	}

	ProgramStateRef stateTrue, stateFalse;
	std::tie(stateTrue, stateFalse) = C.getState()->assume(compareVal.castAs<DefinedSVal>());
	if (stateTrue) {
		return false;
	}

	return true;
}

void ReadlinkChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "ReadlinkChecker"));

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::ReadlinkChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ReadlinkChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerReadlinkChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ReadlinkChecker>();
}

bool ento::shouldRegisterReadlinkChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::C);
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
	registry.addChecker<ReadlinkChecker>("anzu.ReadlinkChecker", "Checks for potential buffer overflow with readlink().", "");
}

#endif
