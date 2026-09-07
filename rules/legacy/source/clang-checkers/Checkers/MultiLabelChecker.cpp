#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindLabelStmtVisitor
		: public RecursiveASTVisitor<FindLabelStmtVisitor> {
		std::list<const LabelStmt*> StmtList;

	public:
		const std::list<const LabelStmt*>& getStmts() {
			return StmtList;
		}

	public:
		explicit FindLabelStmtVisitor() {}

		bool VisitLabelStmt(const LabelStmt* LS) {
			StmtList.push_back(LS);
			return true;
		}
	};

	class MultiLabelChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

	private:
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void MultiLabelChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	auto FD = dyn_cast<FunctionDecl>(D);
	FindLabelStmtVisitor Visitor;
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	AnalysisDeclContext* AC = Mgr.getAnalysisDeclContext(D);
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::MultiLabelChecker, lang);
	auto& Stmts = Visitor.getStmts();
	for (auto LS : Stmts) {
		if (auto SLS = LS->getSubStmt()) {
			if (dyn_cast<LabelStmt>(SLS)) {
				reportBug(FD, Msg, LS->getBeginLoc(), BR);
			}
		}
	}
}

void MultiLabelChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "MultiLabelChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "MultiLabelChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMultiLabelChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MultiLabelChecker>();
}

bool ento::shouldRegisterMultiLabelChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MultiLabelChecker>("anzu.MultiLabelChecker", "Checks for redundant multi-labels", "");
}

#endif