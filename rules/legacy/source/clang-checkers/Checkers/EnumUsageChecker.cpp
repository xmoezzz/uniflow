#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Expr.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class EnumUsageChecker : public Checker<check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		bool GetEnumType(CheckerContext& C, const Expr* E, QualType& QT) const {
			if (auto DRE = dyn_cast<DeclRefExpr>(E)) {
				if (auto D = DRE->getDecl()) {
					if (auto DSD = dyn_cast<EnumConstantDecl>(D)) {
						if (!C.getASTContext().getLangOpts().CPlusPlus)
							return false;
						QT = DSD->getType().getCanonicalType();
					}
				}
			}

			return true;
		}

		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
			if (C.getASTContext().HasSyntaxErrors()) {
				return;
			}

			if (!B->isComparisonOp())
				return;

			QualType LHS_Type = B->getLHS()->IgnoreParenImpCasts()->getType();
			QualType RHS_Type = B->getRHS()->IgnoreParenImpCasts()->getType();
			if (!LHS_Type->isEnumeralType() &&
				!RHS_Type->isEnumeralType())
				return;

			if (!LHS_Type->isEnumeralType()) {
				if (!GetEnumType(C, B->getLHS()->IgnoreParenImpCasts(), LHS_Type)) {
					return;
				}
			}

			if (!RHS_Type->isEnumeralType()) {
				if (!GetEnumType(C, B->getRHS()->IgnoreParenImpCasts(), RHS_Type)) {
					return;
				}
			}

			if (!C.getASTContext().hasSameType(LHS_Type, RHS_Type)) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}

				reportBug(FD, B->getOperatorLoc(), C.getBugReporter());
			}
		}

		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "EnumUsageChecker"));

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::EnumUsageChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "EnumUsageChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerEnumUsageChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<EnumUsageChecker>();
}

bool ento::shouldRegisterEnumUsageChecker(const CheckerManager& mgr) {
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
	registry.addChecker<EnumUsageChecker>("anzu.EnumUsageChecker", "Disallow out-of-bound usage of enum types", "");
}

#endif