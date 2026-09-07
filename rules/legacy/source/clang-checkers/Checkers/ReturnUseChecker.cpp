#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/Analysis/CFG.h"
#include "llvm/Analysis/DominanceFrontier.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/Support/GenericDomTree.h"
#include "llvm/IR/Dominators.h"
#include "clang/Analysis/Analyses/Dominators.h"
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

	class ReturnUseChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		ReturnUseChecker() {}

		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			if (Mgr.getASTContext().HasSyntaxErrors()) {
				return;
			}
			if (const auto* FD = dyn_cast<FunctionDecl>(D)) {
				if (auto Body = FD->getBody()) {
					if (!FD->getReturnType()->isVoidType()) {
						FindReturnStmtVisitor Visitor;
						Visitor.TraverseDecl((FunctionDecl*)FD);
						auto Exprs = Visitor.getExprs();
						for (auto RS : Exprs) {
							if (!RS->getRetValue()) {
								reportBug(FD, RS->getEndLoc(), BR);
							}
						}

						if (Exprs.empty()) {
							reportBug(FD, Body->getEndLoc(), BR);
						}
					}
				}
			}
		}

		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "ReturnUseChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::ReturnUseChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "ReturnUseChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}

	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerReturnUseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ReturnUseChecker>();
}

bool ento::shouldRegisterReturnUseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ReturnUseChecker>("anzu1.ReturnUseChecker", "Functions must have return statements.", "");
}

#endif