#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/Expr.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class FindNullExprVisitor
		: public RecursiveASTVisitor<FindNullExprVisitor> {
		ASTContext& AST;
		std::list<const IntegerLiteral*> StmtList;
		std::set<const IntegerLiteral*> IgnoreSet;

	public:
		FindNullExprVisitor(ASTContext& AST) :AST(AST) {}
		const std::list<const IntegerLiteral*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitIntegerLiteral(const IntegerLiteral* IL) {
			if (IL && IL->getValue() == 0) {
				if (IL->getBeginLoc().isMacroID()) {
					if ("NULL" == getSourceCode(AST, IL)) {
						if (IgnoreSet.find(IL) == IgnoreSet.end()) {
							StmtList.push_back(IL);
						}
					}
				}
			}
			return true;
		}

		bool VisitCastExpr(const CastExpr* CE) {
			if (CE) {
				if (auto Sub = CE->getSubExpr()) {
					if (CE->getType()->isPointerType()) {
						if (auto IL = dyn_cast<IntegerLiteral>(Sub->IgnoreParens())) {
							if (IL->getValue() == 0) {
								if (IL->getBeginLoc().isMacroID()) {
									IgnoreSet.insert(IL);
								}
							}
						}
					}
				}
			}
			return true;
		}
	};

	class NullAsIntChecker : public Checker<check::PreStmt<ImplicitCastExpr>, check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const ImplicitCastExpr* ICE, CheckerContext& C) const;
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
	private:
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void NullAsIntChecker::checkPreStmt(const ImplicitCastExpr* ICE, CheckerContext& C) const {
	const Expr* SubExpr = ICE->getSubExpr()->IgnoreParenImpCasts();
	if (const CXXNullPtrLiteralExpr* NullPtrExpr = llvm::dyn_cast_or_null<CXXNullPtrLiteralExpr>(SubExpr)) {
		if (ICE->getType()->isIntegerType()) {
			std::string Msg = "NULL should not be used as an integer 0";

			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, Msg, ICE->getBeginLoc(), C.getBugReporter());
		}
	}
}

void NullAsIntChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const
{
	const FunctionDecl* FD = dyn_cast<FunctionDecl>(D);
	FindNullExprVisitor Visitor(Mgr.getASTContext());
	Visitor.TraverseDecl(const_cast<Decl*>(D));
	auto Stmts = Visitor.getStmts();
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::NullAsIntChecker, lang);
	for (auto IL : Stmts) {
		reportBug(FD, Msg, IL->getBeginLoc(), BR);
	}
}

void NullAsIntChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "NullAsIntChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "NullAsIntChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerNullAsIntChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<NullAsIntChecker>();
}

bool ento::shouldRegisterNullAsIntChecker(const CheckerManager& mgr) {
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
	registry.addChecker<NullAsIntChecker>("anzu.NullAsIntChecker", "Prohibits the use of NULL as integer 0", "");
}

#endif