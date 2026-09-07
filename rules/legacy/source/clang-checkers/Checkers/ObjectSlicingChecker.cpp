#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include <clang/StaticAnalyzer/Core/BugReporter/BugType.h>
#include <clang/StaticAnalyzer/Core/Checker.h>
#include <clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class ObjectSlicingChecker : public Checker<check::PreStmt<CXXConstructExpr>, check::PreStmt<CXXOperatorCallExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const CXXConstructExpr* CCE, CheckerContext& C) const;
		void checkPreStmt(const CXXOperatorCallExpr* COCE, CheckerContext& C) const;

		void checkExpr(const Expr* E, const CXXRecordDecl* RD, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void ObjectSlicingChecker::checkPreStmt(const CXXConstructExpr* CCE, CheckerContext& C) const {
		if (1 != CCE->getNumArgs())
			return;

		auto Arg = CCE->getArg(0);
		if (!Arg)
			return;

		auto CtorD = CCE->getConstructor();
		if (!CtorD)
			return;

		checkExpr(Arg, CtorD->getParent(), C);
	}

	void ObjectSlicingChecker::checkPreStmt(const CXXOperatorCallExpr* COCE, CheckerContext& C) const {
		if (COCE->getOperator() != OO_Equal)
			return;

		auto Num = COCE->getNumArgs();
		if (2 != Num)
			return;

		auto LHS = COCE->getArg(0);
		auto RHS = COCE->getArg(1);
		if (!LHS || !RHS)
			return;

		auto RD = LHS->getType()->getAsCXXRecordDecl();
		checkExpr(RHS, RD, C);
	}

	void ObjectSlicingChecker::checkExpr(const Expr* E, const CXXRecordDecl* RD, CheckerContext& C) const {
		if (!E || !RD)
			return;

		auto CE = dyn_cast<CastExpr>(E->IgnoreParens());
		if (!CE)
			return;

		if (CE->getCastKind() != CK_DerivedToBase)
			return;

		const Expr* SubE = CE->getSubExpr();
		if (!SubE)
			return;

		QualType DerivedType = C.getASTContext().getCanonicalType(SubE->getType());
		QualType BaseType = C.getASTContext().getCanonicalType(CE->getType());
		auto BaseRD = BaseType->getAsCXXRecordDecl();
		if (!BaseRD)
			return;

		if (BaseRD != RD)
			return;

		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}

		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::ObjectSlicingChecker, lang);
		std::string dt = DerivedType.getAsString();
		std::string bt = BaseType.getAsString();
		std::string Msg = std::vformat(fmt, std::make_format_args(dt, bt));
		reportBug(FD, Msg, E->getBeginLoc(), C.getBugReporter());
	}

	void ObjectSlicingChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "ObjectSlicingChecker"));

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "ObjectSlicingChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerObjectSlicingChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ObjectSlicingChecker>();
}

bool ento::shouldRegisterObjectSlicingChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::CPP);
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
	registry.addChecker<ObjectSlicingChecker>("anzu.ObjectSlicingChecker", "", "");
}

#endif
