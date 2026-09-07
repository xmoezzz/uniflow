#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class PointerCastIntegerChecker : public Checker<check::PreStmt<ExplicitCastExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const ExplicitCastExpr* ECE, CheckerContext& C) const {
			auto DstType = ECE->getType();
			auto SrcType = ECE->getSubExpr()->getType();
			
			if (DstType->isPointerType() && SrcType->isIntegerType() ||
				SrcType->isPointerType() && DstType->isIntegerType()) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}

				reportBug(FD, ECE, C.getBugReporter());
			}
		}

		void reportBug(const Decl* FD, const Expr* E, BugReporter& BR) const {
			auto Loc1 = E->getBeginLoc();
			if (Loc1.isMacroID())
				return;

			if (!BT) {
				BT.reset(new BuiltinBug(this, "PointerCastIntegerChecker"));
			}

			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::PointerCastIntegerChecker, lang);
			PathDiagnosticLocation Loc(Loc1, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, 
				Msg, 
				createRuleExtData(1, "PointerCastIntegerChecker"), 
				Loc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}

	};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPointerCastIntegerChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PointerCastIntegerChecker>();
}

bool ento::shouldRegisterPointerCastIntegerChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PointerCastIntegerChecker>("anzu.PointerCastIntegerChecker", "", "");
}

#endif
