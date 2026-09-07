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
	class BitTypeWithCondChecker : public Checker<check::BranchCondition> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkBranchCondition(const Stmt * Condition, CheckerContext & C) const;
		bool isOneBitSignedInt(ASTContext& AST, const Expr* E) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void BitTypeWithCondChecker::checkBranchCondition(const Stmt* Condition, CheckerContext& C) const {
	if (Condition) {
		if (auto BO = dyn_cast<BinaryOperator>(Condition)) {
			if (BO->isAdditiveOp() || BO->isMultiplicativeOp() || BO->isRelationalOp()) {
				if (isOneBitSignedInt(C.getASTContext(), BO->getLHS())) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}
					reportBug(FD, BO->getLHS()->getBeginLoc(), C.getBugReporter());
				}
				if (isOneBitSignedInt(C.getASTContext(), BO->getRHS())) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}
					reportBug(FD, BO->getRHS()->getBeginLoc(), C.getBugReporter());
				}
			}
		}
	}
}

bool BitTypeWithCondChecker::isOneBitSignedInt(ASTContext& AST, const Expr* E) const {
	if (!E)
		return false;

	if (auto ME = dyn_cast<MemberExpr>(E->IgnoreParenCasts())) {
		if (auto MD = ME->getMemberDecl()) {
			if (auto FD = dyn_cast<FieldDecl>(MD)) {
				if (FD->isBitField() && FD->getType()->isSignedIntegerType()) {
					if (auto BitWidthExpr = FD->getBitWidth()) {
						llvm::APSInt BitWidth = BitWidthExpr->EvaluateKnownConstInt(AST);
						if (BitWidth < 2) {
							return true;
						}
					}
				}
			}
		}
	}
	
	return false;
}

void BitTypeWithCondChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "BitTypeWithCondChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::BitTypeWithCondChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "BitTypeWithCondChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}


/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBitTypeWithCondChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BitTypeWithCondChecker>();
}

bool ento::shouldRegisterBitTypeWithCondChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BitTypeWithCondChecker>("anzu.BitTypeWithCondChecker", "Disable only 1 signed integer", "");
}

#endif