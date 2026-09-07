#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindDeclStmtVisitor
		: public RecursiveASTVisitor<FindDeclStmtVisitor> {
		std::list<const DeclStmt*> StmtList;

	public:
		const std::list<const DeclStmt*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitDeclStmt(const DeclStmt* DS) {
			int Num = 0;
			for (const auto* D : DS->decls()) {
				if (isa<VarDecl>(D)) {
					if (++Num > 1) {
						StmtList.push_back(DS);
						break;
					}
				}
			}
			return true;
		}
	};

	class SingleDeclarationChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::SingleDeclarationChecker, lang);

			FindDeclStmtVisitor Visitor;
			Visitor.TraverseDecl(const_cast<Decl*>(D));
			auto& Stmts = Visitor.getStmts();
			for (auto DS : Stmts) {
				reportBug(D, Msg, DS->getBeginLoc(), BR);
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "SingleDeclarationChecker"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "SingleDeclarationChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSingleDeclarationChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SingleDeclarationChecker>();
}

bool ento::shouldRegisterSingleDeclarationChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SingleDeclarationChecker>("anzu.SingleDeclarationChecker", "Disallow multiple declarations in a single statement", "");
}

#endif