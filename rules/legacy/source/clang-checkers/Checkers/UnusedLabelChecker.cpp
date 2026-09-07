#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class UnusedLabelVisitor : public RecursiveASTVisitor<UnusedLabelVisitor> {
		std::list<Stmt*> Stmts;

	public:
		const std::list<Stmt*>& GetStmts() {
			return Stmts;
		}

		bool VisitLabelStmt(LabelStmt* LS) {
			if (auto LD = LS->getDecl()) {
				if (!LD->isUsed()) {
					Stmts.push_back(LS);
				}
			}
			return true;
		}
	};

	class UnusedLabelChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;
	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			UnusedLabelVisitor Visitor;
			Visitor.TraverseDecl(const_cast<Decl*>(D));
			auto& Stmts = Visitor.GetStmts();
			for (auto& S : Stmts) {
				reportBug(D, S->getBeginLoc(), BR);
			}
		}

		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "UnusedLabelChecker"));
			}

			// Report the issue        
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::UnusedLabelChecker, lang);			
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "UnusedLabelChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUnusedLabelChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UnusedLabelChecker>();
}

bool ento::shouldRegisterUnusedLabelChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UnusedLabelChecker>("anzu.UnusedLabelChecker", "Detects unused labels", "");
}

#endif