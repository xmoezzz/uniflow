#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FindNullStmtVisitor
		: public RecursiveASTVisitor<FindNullStmtVisitor> {
		std::list<const Stmt*> StmtList;
		ASTContext& AST;

	public:
		FindNullStmtVisitor(ASTContext& AST) : AST(AST) {}
		const std::list<const Stmt*>& getStmts() {
			return StmtList;
		}

	private:
		bool IsSameLine(const Stmt* S1, const Stmt* S2) const {
			auto Line1 = AST.getSourceManager().getPresumedLineNumber(S1->getBeginLoc());
			auto Line2 = AST.getSourceManager().getPresumedLineNumber(S2->getBeginLoc());
			return Line1 == Line2;
		}

	public:
		bool VisitIfStmt(const IfStmt* IS) {
			if (auto Then = IS->getThen()) {
				if (isa<NullStmt>(Then)) {
					if (IsSameLine(IS, Then)) {
						StmtList.push_back(Then);
					}
				}
			}
			return true;
		}

		bool VisitDoStmt(const DoStmt* DS) {
			if (auto Body = DS->getBody()) {
				if (isa<NullStmt>(Body)) {
					if (IsSameLine(DS, Body)) {
						StmtList.push_back(Body);
					}
				}
			}
			return true;
		}

		bool VisitWhileStmt(const WhileStmt* WS) {
			if (auto Body = WS->getBody()) {
				if (isa<NullStmt>(Body)) {
					if (IsSameLine(WS, Body)) {
						StmtList.push_back(Body);
					}
				}
			}
			return true;
		}

		bool VisitForStmt(const ForStmt* FS) {
			if (auto Body = FS->getBody()) {
				if (isa<NullStmt>(Body)) {
					if (IsSameLine(FS, Body)) {
						StmtList.push_back(Body);
					}
				}
			}
			return true;
		}
	};

	class SuspiciousSemicolonChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

}

void SuspiciousSemicolonChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const {
	if (!D)
		return;

	auto& Ctx = BR.getContext();
	auto& SM = BR.getSourceManager();
	const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);

	if (!FD || !FD->hasBody())
		return;

	FindNullStmtVisitor Visitor(Mgr.getASTContext());
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	for (auto S : Stmts) {
		reportBug(FD, S->getBeginLoc(), BR);
	}
}


void SuspiciousSemicolonChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;

	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "SuspiciousSemicolonChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::SuspiciousSemicolonChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg,
		createRuleExtData(1, "SuspiciousSemicolonChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSuspiciousSemicolonChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SuspiciousSemicolonChecker>();
}

bool ento::shouldRegisterSuspiciousSemicolonChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SuspiciousSemicolonChecker>("anzu.SuspiciousSemicolonChecker", "Check suspicious semicolon", "");
}

#endif