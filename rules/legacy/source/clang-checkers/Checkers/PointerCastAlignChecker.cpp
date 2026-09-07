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
	class PointerCastAlignChecker : public Checker<check::PreStmt<ExplicitCastExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const ExplicitCastExpr* ECE, CheckerContext& C) const {
			if (auto R = C.getSVal(ECE->getSubExpr()).getAsRegion()) {
				if (auto TVR = dyn_cast<TypedValueRegion>(R)) {
					auto Size = C.getASTContext().getTypeAlign(TVR->getValueType());
					Size = Size;
				}
			}

			if (auto M = C.getSVal(ECE->getSubExpr()).getAsSymbol()) {
				auto Size = C.getASTContext().getTypeAlign(M->getType().getTypePtr());
				Size = Size;
			}
			

			auto DstType = ECE->getType().getTypePtr();
			auto SrcType = ECE->getSubExpr()->getType().getTypePtr();
			if (!DstType || !SrcType)
				return;

			auto DT = dyn_cast<PointerType>(DstType);
			auto ST = dyn_cast<PointerType>(SrcType);
			if (!DT || !ST)
				return;

			auto DA = C.getASTContext().getTypeAlign(DT->getPointeeType());
			auto SA = C.getASTContext().getTypeAlign(ST->getPointeeType());
			if (SA >= DA)
				return;

			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}

			reportBug(FD, ECE, C.getBugReporter());
		}

		void reportBug(const Decl* FD, const Expr* E, BugReporter& BR) const {
			auto Loc1 = E->getBeginLoc();
			if (Loc1.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(this, "PointerCastAlignChecker"));
			}

			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::PointerCastAlignChecker, lang);
			PathDiagnosticLocation Loc(Loc1, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "PointerCastAlignChecker"), Loc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}

	};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPointerCastAlignChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PointerCastAlignChecker>();
}

bool ento::shouldRegisterPointerCastAlignChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PointerCastAlignChecker>("anzu1.PointerCastAlignChecker", "Do not convert pointers to pointer types with stricter alignment requirements", "");
}

#endif
