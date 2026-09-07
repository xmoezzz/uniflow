#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class PointerAlignChecker : public Checker<check::PreStmt<ExplicitCastExpr>, check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreStmt(const ExplicitCastExpr* CE, CheckerContext& C) const;
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		bool isNotAlginOffset(const Expr* LHS, const Expr* RHS, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const std::string& RuleId, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void PointerAlignChecker::checkPreStmt(const ExplicitCastExpr* CE, CheckerContext& C) const {
	if (auto DT = dyn_cast<PointerType>(CE->getType())) {
		if (auto ST = dyn_cast<PointerType>(CE->getSubExpr()->IgnoreParenImpCasts()->getType())) {
			if (!DT->isVoidPointerType() && !ST->isVoidPointerType()) {
				auto DA = C.getASTContext().getTypeAlign(DT->getPointeeType());
				auto SA = C.getASTContext().getTypeAlign(ST->getPointeeType());
				if (0 == DA || 0 == SA)
					return;

				if (DA > SA) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}
					auto ls = anzulocalization::LocaleSetting::getInstance();
					uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
					std::string Msg = ls->parseMsgs(anzulocalization::PointerAlignChecker, lang, 0);
					reportBug(FD, Msg, createRuleExtData(1, "PointerAlignChecker.1"), CE->getBeginLoc(), C.getBugReporter());
				}
			}
		}
	}
}

void PointerAlignChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (B->isAdditiveOp() &&
		(B->getLHS()->getType()->isPointerType() || B->getRHS()->getType()->isPointerType())) {
		
		if (!isNotAlginOffset(B->getLHS(), B->getRHS(), C) ||
			!isNotAlginOffset(B->getRHS(), B->getLHS(), C)) {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::PointerAlignChecker, lang, 1);
			reportBug(FD, Msg, createRuleExtData(1, "PointerAlignChecker.2"), B->getOperatorLoc(), C.getBugReporter());
		}
	}
}

bool PointerAlignChecker::isNotAlginOffset(const Expr* LHS, const Expr* RHS, CheckerContext& C) const {
	if (auto R = C.getSVal(LHS).getAsRegion()) {
		if (auto OffsetVal = C.getSVal(RHS).getAs<nonloc::ConcreteInt>()) {
			if (auto ER = dyn_cast<ElementRegion>(R)) {
				if (auto SR = ER->getSuperRegion()) {
					if (auto VR = dyn_cast<VarRegion>(SR)) {
						if (auto D = VR->getDecl()) {
							if (auto VD = dyn_cast<VarDecl>(D)) {
								if (auto AT = dyn_cast<ArrayType>(VD->getType())) {
									auto OriginElemSize = C.getASTContext().getTypeSizeInChars(AT->getElementType());
									auto CurElemSize = C.getASTContext().getTypeSizeInChars(ER->getValueType());
									auto CurElemOffset = ER->getAsArrayOffset().getOffset();

									auto OffsetValue = OffsetVal->getValue().getLimitedValue();
									auto CurOffsetValue = CurElemOffset + CurElemSize * OffsetValue;
									auto Result = CurOffsetValue % OriginElemSize;
									
									return 0 == Result;
								}
							}
						}
					}
				}
			}
		}
	}

	return true;
}

void PointerAlignChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const std::string& RuleId, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "PointerAlignChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, RuleId, DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPointerAlignChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PointerAlignChecker>();
}

bool ento::shouldRegisterPointerAlignChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PointerAlignChecker>("anzu.PointerAlignChecker", "Detection of alignment error of the finger", "");
}

#endif