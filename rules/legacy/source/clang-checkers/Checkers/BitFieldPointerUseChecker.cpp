#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"


using namespace clang;
using namespace ento;

namespace {
	class BitFieldPointerUseChecker : public Checker<check::PreStmt<UnaryOperator>, check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreStmt(const UnaryOperator* UO, CheckerContext& C) const;
		void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const;
		bool isBitField(CheckerContext& C, const Expr* E) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void BitFieldPointerUseChecker::checkPreStmt(const UnaryOperator* UO, CheckerContext& C) const {
	if (UO) {
		if (UO->isIncrementDecrementOp()) {
			if (isBitField(C, UO->getSubExpr()->IgnoreParenCasts())){
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}

				reportBug(FD, UO->getOperatorLoc(), C.getBugReporter());
			}
		}
	}
}

void BitFieldPointerUseChecker::checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const {
	if (BO) {
		if (BO->getOpcode() == BinaryOperator::Opcode::BO_AddAssign ||
			BO->getOpcode() == BinaryOperator::Opcode::BO_SubAssign) {
			if (isBitField(C, BO->getLHS()->IgnoreParenCasts())) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}

				reportBug(FD, BO->getOperatorLoc(), C.getBugReporter());
			}
		}
	}
}

bool BitFieldPointerUseChecker::isBitField(CheckerContext& C, const Expr* E) const {
	if (!E)
		return false;

	auto UO = dyn_cast<UnaryOperator>(E);
	if (!UO)
		return false;

	//E = UO->getSubExpr();
	if (!E)
		return false;

	if (auto R = C.getSVal(E).getAsRegion()) {
		if (auto ER = dyn_cast<ElementRegion>(R)) {
			if (auto SR = ER->getSuperRegion()) {
				if (auto VR = dyn_cast<VarRegion>(SR)) {
					if (auto D = VR->getDecl()) {
						if (auto VD = dyn_cast<VarDecl>(D)) {
							if (auto ET = dyn_cast<ElaboratedType>(VD->getType())) {
								if (auto RT = dyn_cast<RecordType>(ET->getNamedType().getTypePtr())) {
									if (auto RD = RT->getDecl()) {
										auto FirstIsBF = RD->fields().empty() ? false : RD->field_begin()->isBitField();
										auto LastIsBF = false;
										for (auto F : RD->fields()) {
											LastIsBF = F->isBitField();
										}
										if (FirstIsBF || LastIsBF) {
											return true;
										}
									}
								}
							}
						}
					}
				}
			}
		}

		return false;
	}
}

void BitFieldPointerUseChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "BitFieldPointerUseChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::BitFieldPointerUseChecker, lang);
	auto Report = std::make_unique<BasicBugReport>(*BT, Msg, createRuleExtData(1, "BitFieldPointerUseChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}


/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBitFieldPointerUseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BitFieldPointerUseChecker>();
}

bool ento::shouldRegisterBitFieldPointerUseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BitFieldPointerUseChecker>("anzu.BitFieldPointerUseChecker", "Don’t make assumptions about the structure’s segment layout", "");
}

#endif