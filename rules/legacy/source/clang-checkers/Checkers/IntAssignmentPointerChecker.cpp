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
	class IntAssignmentPointerChecker : public Checker<check::Bind> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkBind(SVal L, SVal V, const Stmt* S, CheckerContext& C) const {
			const FunctionDecl* FD = nullptr;
			if (auto LC = C.getLocationContext()) {
				if (auto D = LC->getDecl()) {
					FD = dyn_cast<FunctionDecl>(D);
				}
			}

			if (const auto* BO = llvm::dyn_cast_or_null<BinaryOperator>(S)) {
				if (const auto* CastE = llvm::dyn_cast_or_null<CastExpr>(BO->getRHS()->IgnoreParenImpCasts())) {
					QualType DestTy = CastE->getType();
					QualType SourceTy = CastE->getSubExpr()->getType();

					if (DestTy->isPointerType() && SourceTy->isIntegerType()) {
						if (!isZero(CastE->getSubExpr())) {
							auto ls = anzulocalization::LocaleSetting::getInstance();
							uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
							std::string Msg = ls->parseMsgs(anzulocalization::IntAssignmentPointerChecker, lang);

							reportBug(FD, Msg, BO->getOperatorLoc(), C.getBugReporter());
						}
					}
				}
			}
		}

		bool isZero(const Expr* E) const {
			if (!E) {
				return false;
			}

			E = E->IgnoreParenCasts();
			if (auto IL = dyn_cast<IntegerLiteral>(E)) {
				return IL->getValue() == 0;
			}

			return false;
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "IntAssignmentPointerChecker"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "IntAssignmentPointerChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerIntAssignmentPointerChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<IntAssignmentPointerChecker>();
}

bool ento::shouldRegisterIntAssignmentPointerChecker(const CheckerManager& mgr) {
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
	registry.addChecker<IntAssignmentPointerChecker>("anzu.IntAssignmentPointerChecker", "", "");
}

#endif
