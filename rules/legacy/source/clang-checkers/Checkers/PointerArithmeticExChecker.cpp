#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class PointerArithmeticExChecker : public Checker<check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		bool checkPointerOffset(const Expr* Pointer, const Expr* Offset, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void PointerArithmeticExChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (C.getASTContext().HasSyntaxErrors())
		return;

	if (B->isAdditiveOp() &&
		(B->getLHS()->getType()->isPointerType() || B->getRHS()->getType()->isPointerType())) {
		// fix: forearch bug
		if (B->getOpcode() == BinaryOperator::Opcode::BO_Add) {
			if (auto DRE = dyn_cast<DeclRefExpr>(B->getLHS()->IgnoreParenImpCasts())) {
				if (auto D = DRE->getDecl()) {
					if (D->getNameAsString() == "__range1") {
						return;
					}
				}
			}
		}
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::PointerArithmeticExChecker, lang);
		if (!checkPointerOffset(B->getLHS(), B->getRHS(), C)) {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}

			reportBug(FD, Msg, B->getRHS()->getExprLoc(), C.getBugReporter());
		}
		else if (!checkPointerOffset(B->getRHS(), B->getLHS(), C)) {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}

			reportBug(FD, Msg, B->getLHS()->getExprLoc(), C.getBugReporter());
		}
	}
}

bool PointerArithmeticExChecker::checkPointerOffset(const Expr* Pointer, const Expr* Offset, CheckerContext& C) const {
	if (auto R = C.getSVal(Pointer).getAsRegion()) {
		if (auto OffsetVal = C.getSVal(Offset).getAs<nonloc::ConcreteInt>()) {
			if (auto ER = dyn_cast<ElementRegion>(R)) {
				if (auto SR = ER->getSuperRegion()) {
					if (auto VR = dyn_cast<VarRegion>(SR)) {
						if (auto D = VR->getDecl()) {
							if (auto VD = dyn_cast<VarDecl>(D)) {
								if (auto AT = dyn_cast<ArrayType>(VD->getType().getTypePtr())) {
									auto OriginArraySize = C.getASTContext().getTypeSizeInChars(AT);
									auto OriginElemSize = C.getASTContext().getTypeSizeInChars(AT->getElementType());
									if (OriginElemSize.isZero())
										return true;

									auto Length = OriginArraySize / OriginElemSize;
									auto OffsetValue = OffsetVal->getValue().getLimitedValue();
									return OffsetValue < Length;
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

void PointerArithmeticExChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "PointerArithmeticExChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "PointerArithmeticExChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPointerArithmeticExChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PointerArithmeticExChecker>();
}

bool ento::shouldRegisterPointerArithmeticExChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PointerArithmeticExChecker>("anzu1.PointerArithmeticExChecker", "Prohibit logical comparisons between pointers", "");
}

#endif