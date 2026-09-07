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
	class FindCastsVisitor
		: public RecursiveASTVisitor<FindCastsVisitor> {
		std::list<const CStyleCastExpr*> Exprs;

	public:
		const std::list<const CStyleCastExpr*>& getExprs() {
			return Exprs;
		}

	public:
		bool VisitCStyleCastExpr(const CStyleCastExpr* CE) {
			if (CE) {
				if (CE->getType()->isPointerType() &&
					!CE->getSubExpr()->getType()->isPointerType()) {

					Exprs.push_back(CE);
				}
			}
			return true;
		}
	};

	class ForcedPointerCastChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		ForcedPointerCastChecker() {}

		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

		bool isZero(const Expr* E) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
} // end anonymous namespace

void ForcedPointerCastChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	if (Mgr.getASTContext().HasSyntaxErrors()) {
		return;
	}

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::ForcedPointerCastChecker, lang);
	auto FD = dyn_cast<FunctionDecl>(D);
	FindCastsVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	AnalysisDeclContext* AC = Mgr.getAnalysisDeclContext(D);
	auto Exprs = Visitor.getExprs();
	for (auto CE : Exprs) {
		if (!isZero(CE->getSubExpr()))
			reportBug(FD, Msg, CE->getBeginLoc(), BR);
	}
}

bool ForcedPointerCastChecker::isZero(const Expr* E) const {
	if (!E) {
		return false;
	}

	E = E->IgnoreParenCasts();
	if (auto IL = dyn_cast<IntegerLiteral>(E)) {
		return IL->getValue() == 0;
	}

	return false;
}

void ForcedPointerCastChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ForcedPointerCastChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ForcedPointerCastChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerForcedPointerCastChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ForcedPointerCastChecker>();
}

bool ento::shouldRegisterForcedPointerCastChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ForcedPointerCastChecker>("anzu.ForcedPointerCastChecker", "", "");
}

#endif


