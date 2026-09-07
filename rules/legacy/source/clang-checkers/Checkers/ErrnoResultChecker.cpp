#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <vector>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	std::set<std::string> ErrnoFunctions = {
		"ftell","fgetpos","fsetpos","mbrtowc",
		"mbsrtowcs","signal","wcrtomb","wcsrtombs",
		"mbrtoc16","mbrtoc32","c16rtomb","cr32rtomb",
		"fgetwc","fputwc","strtol","wcstol",
		"strtoll","wcstoll","strtoul","wcstoul",
		"strtoull","wcstoull","strtoumax","wcstoumax",
		"strtod","wcstod","strtof","wcstof",
		"strtold","wcstold","strtoimax","wcstoimax",
	};

	enum ERRNO_STATUS {
		ERRNO_STATUS_RESET,
		ERRNO_STATUS_CHECK,
	};

	class FindErrnoRefVisitor
		: public RecursiveASTVisitor<FindErrnoRefVisitor> {
		bool Ref = false;

	public:
		bool isRef() {
			return Ref;
		}

	public:
		bool VisitDeclRefExpr(const DeclRefExpr* DRE) {
			if (DRE) {
				if (auto D = DRE->getDecl()) {
					if (auto VD = dyn_cast<VarDecl>(D)) {
						if (VD->hasGlobalStorage()) {
							if (VD->getNameAsString() == "errno") {
								Ref = true;
								return false;
							}
						}
					}
				}
			}
			return true;
		}

		bool VisitUnaryOperator(const UnaryOperator* UO) {
			if (UO && UO->getOpcode() == UnaryOperator::Opcode::UO_Deref) {
				if (auto SubExpr = UO->getSubExpr()) {
					if (auto CE = dyn_cast<CallExpr>(SubExpr->IgnoreParenCasts())) {
						if (auto FD = CE->getDirectCallee()) {
							if (FD->isGlobal() && FD->getNameAsString() == "_errno") {
								Ref = true;
								return false;
							}
						}
					}
				}
			}
			return true;
		}
	};

	class ErrnoResultChecker : public Checker<check::PostStmt<BinaryOperator>,
		check::PostCall,
		check::BranchCondition> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPostStmt(const BinaryOperator* BO, CheckerContext& C) const;
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;
		void checkBranchCondition(const Stmt* S, CheckerContext& C) const;

	private:
		bool checkLeak(SymbolRef Sym, ERRNO_STATUS State, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

//REGISTER_TRAIT_WITH_PROGRAMSTATE(ErrnoStatus, ERRNO_STATUS);
REGISTER_MAP_WITH_PROGRAMSTATE(ErrnoStatus, ERRNO_STATUS, const Expr*)

void ErrnoResultChecker::checkPostStmt(const BinaryOperator* BO, CheckerContext& C) const {
	if (auto LHS = BO->getLHS()) {
		if (auto DRE = dyn_cast<DeclRefExpr>(LHS->IgnoreImpCasts())) {
			if (auto D = DRE->getDecl()) {
				if (auto VD = dyn_cast<VarDecl>(D)) {
					if (VD->hasGlobalStorage()) {
						if (VD->getNameAsString() == "errno") {
							auto State = C.getState();
							State = State->set<ErrnoStatus>(ERRNO_STATUS_RESET, nullptr);
							C.addTransition(State);
						}
					}
				}
			}
		}
		else if (auto UO = dyn_cast<UnaryOperator>(LHS->IgnoreParenCasts())) {
			if (UO->getOpcode() == UnaryOperator::Opcode::UO_Deref) {
				if (auto SubExpr = UO->getSubExpr()) {
					if (auto CE = dyn_cast<CallExpr>(SubExpr->IgnoreParenCasts())) {
						if (auto FD = CE->getDirectCallee()) {
							if (FD->isGlobal() && FD->getNameAsString() == "_errno") {
								auto State = C.getState();
								State = State->set<ErrnoStatus>(ERRNO_STATUS_RESET, nullptr);
								C.addTransition(State);
							}
						}
					}
				}
			}
		}
	}
}

void ErrnoResultChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
	auto II = Call.getCalleeIdentifier();
	if (!II)
		return;

	if (ErrnoFunctions.find(II->getName().str()) == ErrnoFunctions.end())
		return;

	//if (!Call.isInSystemHeader())
		//return;

	auto State = C.getState();
	auto Status = State->get<ErrnoStatus>();
	if (Status.isEmpty()) {
		State = State->set<ErrnoStatus>(ERRNO_STATUS_CHECK, Call.getOriginExpr());
	}
	else if (!Status.contains(ERRNO_STATUS_RESET)) {
		State = State->set<ErrnoStatus>(ERRNO_STATUS_CHECK, Call.getOriginExpr());
	}
	else {
		State = State->remove<ErrnoStatus>(ERRNO_STATUS_RESET);
	}

	C.addTransition(State);
}

void ErrnoResultChecker::checkBranchCondition(const Stmt* S, CheckerContext& C) const {
	if (!S)
		return;

	FindErrnoRefVisitor Visitor;
	Visitor.TraverseStmt(const_cast<Stmt*>(S));
	if (Visitor.isRef()) {
		auto State = C.getState();
		auto Status = State->get<ErrnoStatus>();
		if (Status.contains(ERRNO_STATUS_CHECK)) {
			if (auto IT = Status.lookup(ERRNO_STATUS_CHECK)) {
				if (auto CE = *IT) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}

					reportBug(FD, CE->getBeginLoc(), C.getBugReporter());
				}
			}
			State = State->remove<ErrnoStatus>(ERRNO_STATUS_RESET);
			C.addTransition(State);
		}
	}
}

void ErrnoResultChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ErrnoResultChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::ErrnoResultChecker, lang);
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ErrnoResultChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerErrnoResultChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ErrnoResultChecker>();
}

bool ento::shouldRegisterErrnoResultChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ErrnoResultChecker>("anzu.ErrnoResultChecker", "", "");
}

#endif
