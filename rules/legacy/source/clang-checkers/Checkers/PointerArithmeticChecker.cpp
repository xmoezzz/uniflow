#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class PointerArithmeticChecker : public Checker<check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void PointerArithmeticChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
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

		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::PointerArithmeticChecker, lang);
		reportBug(FD, Msg, B->getOperatorLoc(), C.getBugReporter());
	}
}

void PointerArithmeticChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "PointerArithmeticChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "PointerArithmeticChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPointerArithmeticChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PointerArithmeticChecker>();
}

bool ento::shouldRegisterPointerArithmeticChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PointerArithmeticChecker>("anzu.PointerArithmeticChecker", "Prohibit logical comparisons between pointers", "");
}

#endif