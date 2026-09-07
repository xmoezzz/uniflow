#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindCallExprVisitor
		: public RecursiveASTVisitor<FindCallExprVisitor> {
		const CallExpr* CE = nullptr;
		const FunctionDecl* FD = nullptr;

	public:
		FindCallExprVisitor(const FunctionDecl* FD) : FD(FD) {}
		const CallExpr* GetCallExpr() {
			return CE;
		}

	public:
		bool VisitCallExpr(const CallExpr* CE) {
			if (CE) {
				if (CE->getDirectCallee() == FD) {
					this->CE = CE;
					return false;
				}
			}
			return true;
		}
	};

	class ReentryChecker : public Checker<check::PreStmt<DeclStmt>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreStmt(const DeclStmt* DS, CheckerContext& C) const {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			if (!FD)
				return;

			for (auto D : DS->decls()) {
				if (auto VD = dyn_cast<VarDecl>(D)) {
					if (auto Init = VD->getInit()) {
						FindCallExprVisitor Visitor(FD);
						Visitor.TraverseStmt(const_cast<Expr*>(Init));
						if (auto CE = Visitor.GetCallExpr()) {
							reportBug(FD, CE->getBeginLoc(), C.getBugReporter());
						}
					}
				}
			}
		}

	private:
		bool containsStaticLocal(const DeclStmt* DS, const CallExpr* CE) const {
			for (const Decl* D : DS->decls()) {
				if (const VarDecl* VD = llvm::dyn_cast_or_null<VarDecl>(D)) {
					if (VD->isStaticLocal()) {
						if (auto Init = VD->getInit()) {
							for (auto CS : Init->children()) {
								if (CE == CS) {
									return true;
								}
							}
						}
					}
				}
			}
			return false;
		}

		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "ReentryChecker"));

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::ReentryChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT,
				Msg,
				createRuleExtData(1, "ReentryChecker"),
				DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end of anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerReentryChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ReentryChecker>();
}

bool ento::shouldRegisterReentryChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ReentryChecker>("anzu.ReentryChecker", "", "");
}

#endif
