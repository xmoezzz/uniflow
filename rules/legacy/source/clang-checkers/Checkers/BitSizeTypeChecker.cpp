#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace
{
	class FindUnIntTypeVisitor
		: public RecursiveASTVisitor<FindUnIntTypeVisitor> {
		const Expr* UnIntExpr = nullptr;
	public:
		const Expr* GetIntExpr() {
			return UnIntExpr;
		}
		bool VisitCastExpr(const CastExpr* CE) {
			if (!CE->getSubExpr()->getType()->isIntegralOrEnumerationType()) {
				UnIntExpr = CE->getSubExpr();
				return false;
			}
			return true;
		}
	};
}

class BitSizeTypeChecker : public Checker<check::ASTDecl<FieldDecl>> {
	mutable std::unique_ptr<BuiltinBug> BT;

public:
	void checkASTDecl(const FieldDecl* D, AnalysisManager& Mgr,
		BugReporter& BR) const {
		ASTContext& Ctx = BR.getContext();
		if (D->isBitField()) {
			Expr* BitWidthExpr = D->getBitWidth();
			FindUnIntTypeVisitor Visitor;
			Visitor.TraverseStmt(BitWidthExpr);

			if (auto E = Visitor.GetIntExpr()) {
				const Decl* FD = nullptr;
				if (auto AC = Mgr.getAnalysisDeclContext(D)) {
					FD = AC->getDecl();
				}

				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::BitSizeTypeChecker, lang);
				reportBug(FD, Msg, E->getBeginLoc(), BR);
			}
		}
	}

	void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "BitSizeTypeChecker"));

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "BitSizeTypeChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
};

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBitSizeTypeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BitSizeTypeChecker>();
}

bool ento::shouldRegisterBitSizeTypeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BitSizeTypeChecker>("anzu.BitSizeTypeChecker", "Prohibit assigning negative values to unsigned type variables", "");
}

#endif