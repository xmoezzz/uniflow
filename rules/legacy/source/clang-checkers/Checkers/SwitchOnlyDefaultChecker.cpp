#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"
#include <regex>  

using namespace clang;
using namespace ento;

namespace {
	class FindSwitchStmtVisitor
		: public RecursiveASTVisitor<FindSwitchStmtVisitor> {
		std::list<const Stmt*> StmtList;

	public:
		const std::list<const Stmt*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitSwitchStmt(const SwitchStmt* SS) {
			int Count = 0;
			bool HasDefault = false;
			for (const SwitchCase* SC = SS->getSwitchCaseList(); SC; SC = SC->getNextSwitchCase()) {
				if (SC) {
					++Count;
					if (dyn_cast<DefaultStmt>(SC)) {
						HasDefault = true;
					}
				}
			}
			if (1 == Count && HasDefault) {
				StmtList.push_back(SS);
			}
			return true;
		}
	};

	class SwitchOnlyDefaultChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void SwitchOnlyDefaultChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	if (Mgr.getASTContext().HasSyntaxErrors()) {
		return;
	}

	auto FD = dyn_cast<FunctionDecl>(D);
	FindSwitchStmtVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto S : Stmts) {
		auto data = getSourceCode(Mgr.getASTContext(), S->getBeginLoc(), S->getEndLoc());
		std::regex pattern("case.*:");
		bool found = std::regex_search(data, pattern);
		if (found)
			reportBug(FD, S->getBeginLoc(), BR);
	}
}

void SwitchOnlyDefaultChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "SwitchOnlyDefaultChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::SwitchOnlyDefaultChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "SwitchOnlyDefaultChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSwitchOnlyDefaultChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SwitchOnlyDefaultChecker>();
}

bool ento::shouldRegisterSwitchOnlyDefaultChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SwitchOnlyDefaultChecker>("anzu1.SwitchOnlyDefaultChecker", "Switch statements containing only the default case are prohibited.", "");
}

#endif