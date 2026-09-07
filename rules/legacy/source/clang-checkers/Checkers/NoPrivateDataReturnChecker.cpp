#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/AST/DeclCXX.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindReturnStmtVisitor
		: public RecursiveASTVisitor<FindReturnStmtVisitor> {
		std::list<const ReturnStmt*> ExprList;

	public:
		const std::list<const ReturnStmt*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitReturnStmt(const ReturnStmt* RS) {
			if (RS) {
				ExprList.push_back(RS);
			}
			return true;
		}
	};

	class NoPrivateDataReturnChecker : public Checker<check::ASTDecl<CXXMethodDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const CXXMethodDecl* MD, AnalysisManager& mgr, BugReporter& BR) const {
			if (!MD) {
				return;
			}

			// Check if method is public.
			if (MD->getAccess() != AS_public) {
				return;
			}

			const QualType ReturnType = MD->getReturnType();
			// Check if method returns reference or pointer.
			if (!ReturnType->isReferenceType() && !ReturnType->isPointerType()) {
				return;
			}

			// Check the function body.
			const Stmt* Body = MD->getBody();
			if (!Body) {
				return;
			}

			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::NoPrivateDataReturnChecker, lang);
			FindReturnStmtVisitor Visitor;
			Visitor.TraverseStmt(const_cast<Stmt*>(Body));
			auto Exprs = Visitor.getExprs();
			for (auto RS : Exprs) {
				if (auto Value = RS->getRetValue()) {
					if (const auto* ME = dyn_cast<MemberExpr>(Value->IgnoreParenCasts())) {
						if (ME->getMemberDecl()->getAccess() == AS_private || ME->getMemberDecl()->getAccess() == AS_protected) {
							reportBug(MD, Msg, Value->getBeginLoc(), BR);
						}
					}
				}
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "NoPrivateDataReturnChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "NoPrivateDataReturnChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerNoPrivateDataReturnChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<NoPrivateDataReturnChecker>();
}

bool ento::shouldRegisterNoPrivateDataReturnChecker(const CheckerManager& mgr) {
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
	registry.addChecker<NoPrivateDataReturnChecker>("anzu.NoPrivateDataReturnChecker", "", "");
}

#endif
