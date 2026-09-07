#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Stmt.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class StrongTypedefReturnMismatchChecker : public Checker<check::PreStmt<ReturnStmt>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		StrongTypedefReturnMismatchChecker() {}

		void checkPreStmt(const ReturnStmt* R, CheckerContext& C) const {
			const Expr* RetExpr = R->getRetValue();
			if (!RetExpr)
				return;

			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				if (auto FD = dyn_cast<FunctionDecl>(ADC->getDecl())) {
					QualType ReturnType = FD->getReturnType();
					QualType ExprType = RetExpr->getType();

					if (isStrongTypedefMismatch(ReturnType, ExprType, C.getASTContext())) {
						reportBug(FD, RetExpr->getBeginLoc(), C.getBugReporter());
					}					
				}
			}
		}

	private:
		bool isStrongTypedefMismatch(QualType ParamType, QualType ArgType, ASTContext& Ctx) const {
			const TypedefType* ParamTypedef = ParamType->getAs<TypedefType>();
			const TypedefType* ArgTypedef = ArgType->getAs<TypedefType>();
			if (!ParamTypedef || !ArgTypedef)
				return false;

			auto ParamTD = ParamTypedef->getDecl();
			auto ArgTD = ArgTypedef->getDecl();
			if (!ParamTD || !ArgTD)
				return false;

			if (ParamTD->getName().empty() || ArgTD->getName().empty())
				return false;

			return ParamTD->getName() != ArgTD->getName();
		}

		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "StrongTypedefReturnMismatchChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::StrongTypedefReturnMismatchChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg,
				createRuleExtData(1, "StrongTypedefReturnMismatchChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerStrongTypedefReturnMismatchChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<StrongTypedefReturnMismatchChecker>();
}

bool ento::shouldRegisterStrongTypedefReturnMismatchChecker(const CheckerManager& mgr) {
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
	registry.addChecker<StrongTypedefReturnMismatchChecker>("anzu.StrongTypedefReturnMismatchChecker", "Detect strong typedef return mismatches", "");
}

#endif