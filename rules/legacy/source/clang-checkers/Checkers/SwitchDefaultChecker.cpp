#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class SwitchDefaultChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
	};

	class Visitor : public RecursiveASTVisitor<Visitor> {
		BugReporter& BR;
		AnalysisManager& Mgr;
		BuiltinBug& BT;
		const FunctionDecl* FD;

	public:
		Visitor(const FunctionDecl* FD, BugReporter& BR, AnalysisManager& Mgr, BuiltinBug& BT)
			: FD(FD), BR(BR), Mgr(Mgr), BT(BT) {}

		bool VisitSwitchStmt(SwitchStmt* SS) {
			const Expr* Cond = SS->getCond()->IgnoreParenImpCasts();
			const EnumType* ET = Cond->getType()->getAs<EnumType>();
			if (!ET)
				return true;

			EnumDecl* ED = ET->getDecl();
			unsigned NumCases = std::distance(ED->enumerator_begin(), ED->enumerator_end());
			unsigned CountedCases = 0;
			bool hasDefault = false;

			for (const SwitchCase* SC = SS->getSwitchCaseList(); SC; SC = SC->getNextSwitchCase()) {
				if (isa<DefaultStmt>(SC)) {
					hasDefault = true;
				}
				else {
					CountedCases++;
				}
			}

			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::SwitchDefaultChecker, lang);
			if (!hasDefault && CountedCases < NumCases) {
				reportBug(FD, Msg, SS->getBeginLoc(), BR);
			}
			return true;
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				BT, Msg, createRuleExtData(1, "SwitchDefaultChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

	void SwitchDefaultChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
		BugReporter& BR) const {
		if (!D)
			return;

		if (!BT)
			BT.reset(new BuiltinBug(this, "SwitchDefaultChecker"));

		Visitor V(dyn_cast<FunctionDecl>(D), BR, Mgr, *BT);
		V.TraverseDecl(const_cast<Decl*>(D));
	}
}


/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSwitchDefaultChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SwitchDefaultChecker>();
}

bool ento::shouldRegisterSwitchDefaultChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SwitchDefaultChecker>("anzu.SwitchDefaultChecker", "", "");
}

#endif