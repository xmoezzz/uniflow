#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindRecoveryExprVisitor
		: public RecursiveASTVisitor<FindRecoveryExprVisitor> {
		std::list<const RecoveryExpr*> ExprList;

	public:
		const std::list<const RecoveryExpr*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitRecoveryExpr(const RecoveryExpr* RE) {
			if (RE) {
				auto Childs = RE->subExpressions();
				if (Childs.size() == 2) {
					ExprList.push_back(RE);
				}
			}
			return true;
		}
	};
	class UnPointerAndPointerAssignChecker : public Checker<check::ASTDecl<VarDecl>, check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			if (Mgr.getASTContext().HasSyntaxErrors()) {
				return;
			}

			if (D) {
				if (auto Init = D->getInit()) {
					if (auto RE = dyn_cast<RecoveryExpr>(Init)) {
						auto Childs = RE->subExpressions();
						if (Childs.size() == 1) {
							if (auto Sub = Childs[0]) {
								if (auto SubE = dyn_cast<Expr>(Sub)) {
									if (D->getType()->isPointerType()) {
										if (SubE->getType()->isIntegerType()) {
											reportBug(findFunctionDecl(D), Init->getBeginLoc(), BR);
										}
									}
									if (D->getType()->isIntegerType()) {
										if (SubE->getType()->isPointerType()) {
											reportBug(findFunctionDecl(D), Init->getBeginLoc(), BR);
										}
									}
								}
							}
						}
					}
				}
			}
		}

		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const {
			if (Mgr.getASTContext().HasSyntaxErrors()) {
				return;
			}

			FindRecoveryExprVisitor Visitor;
			Visitor.TraverseDecl(const_cast<Decl*>(D));
			auto Exprs = Visitor.getExprs();
			for (auto RE : Exprs) {
				checkRecoveryExpr(dyn_cast<FunctionDecl>(D), RE, Mgr, BR);
			}
		}

		void checkRecoveryExpr(const FunctionDecl* FD, const RecoveryExpr* RE, AnalysisManager& Mgr, BugReporter& BR) const {
			if (!RE)
				return;

			auto Childs = RE->subExpressions();
			if (Childs.size() != 2)
				return;

			auto LHS = Childs[0];
			auto RHS = Childs[1];
			if (!LHS || !RHS)
				return;

			auto a = TrimString(ToString(LHS));
			auto b = TrimString(ToString(RHS));
			auto str = TrimString(getSourceCode(Mgr.getASTContext(), LHS->getBeginLoc(), RHS->getEndLoc()));
			if (str.size() <= a.size() + b.size())
				return;

			auto op = str.substr(a.size(), str.size() - a.size() - b.size());
			if (op != "=")
				return;

			if (LHS->getType()->isPointerType()) {
				if (RHS->getType()->isIntegerType()) {
					reportBug(FD, RHS->getBeginLoc(), BR);
				}
			}

			if (LHS->getType()->isIntegerType()) {
				if (RHS->getType()->isPointerType()) {
					reportBug(FD, RHS->getBeginLoc(), BR);
				}
			}
		}

		void reportBug(const Decl* FD, SourceLocation SL, BugReporter& BR) const {
			if (SL.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(this, "UnPointerAndPointerAssignChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::UnPointerAndPointerAssignChecker, lang);        
			PathDiagnosticLocation DLoc(SL, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg,
				createRuleExtData(1, "UnPointerAndPointerAssignChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUnPointerAndPointerAssignChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UnPointerAndPointerAssignChecker>();
}

bool ento::shouldRegisterUnPointerAndPointerAssignChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UnPointerAndPointerAssignChecker>("anzu.UnPointerAndPointerAssignChecker", "When assigning a pointer variable to a non-pointer variable or assigning a non-pointer value to a pointer variable, a cast must be used.", "");
}

#endif
