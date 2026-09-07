#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/AST/StmtCXX.h"
#include "../Utils.h"
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {

	class MemberAccessVisitor : public RecursiveASTVisitor<MemberAccessVisitor> {
		ASTContext& AST;
		const CXXRecordDecl* CurRD = nullptr;
		const Expr* UseME = nullptr;

	public:
		explicit MemberAccessVisitor(ASTContext& AST, const CXXRecordDecl* CurRD) : AST(AST), CurRD(CurRD) { }

		bool VisitMemberExpr(MemberExpr* ME) {
			if (const FieldDecl* FD = llvm::dyn_cast_or_null<FieldDecl>(ME->getMemberDecl())) {
				if (auto RD = dyn_cast<CXXRecordDecl>(FD->getParent())) {
					if (RD == CurRD || isDerivedFrom(RD->getTypeForDecl())) {
						UseME = ME;
						return false;
					}
				}
			}
			return true; // Continue traversal
		}

		bool VisitCXXMemberCallExpr(CXXMemberCallExpr* CE) {
			if (auto RD = CE->getRecordDecl()) {
				if (RD == CurRD || isDerivedFrom(RD->getTypeForDecl())) {
					UseME = CE;
					return false;
				}
			}
			return true; // Continue traversal
		}

		bool isDerivedFrom(const Type* BaseType) const {
			if (!BaseType)
				return false;

			if (auto CurType = CurRD->getTypeForDecl()) {
				const CXXRecordDecl* BaseRD =
					AST.getCanonicalType(BaseType)->getAsCXXRecordDecl();
				const CXXRecordDecl* DerivedRD =
					AST.getCanonicalType(CurType)->getAsCXXRecordDecl();

				if (!BaseRD || !DerivedRD)
					return false;

				return DerivedRD->isDerivedFrom(BaseRD);
			}

			return false;
		}

		const Expr* GetMemberExpr() const {
			return UseME;
		}
	};

	class ConstructorDestructorTryCatchChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			const auto* Constructor = llvm::dyn_cast_or_null<CXXConstructorDecl>(D);
			const auto* Destructor = llvm::dyn_cast_or_null<CXXDestructorDecl>(D);

			if (!Constructor && !Destructor) {
				return;
			}

			const Stmt* Body = D->getBody();
			if (!Body) {
				return;
			}

			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::ConstructorDestructorTryCatchChecker, lang);
			if (const CXXTryStmt* TryStmt = llvm::dyn_cast_or_null<CXXTryStmt>(Body)) {
				const CXXRecordDecl* ContainingClass = nullptr;
				if (Constructor) {
					ContainingClass = Constructor->getParent();
				}
				else if (Destructor) {
					ContainingClass = Destructor->getParent();
				}

				if (ContainingClass) {
					for (unsigned i = 0, e = TryStmt->getNumHandlers(); i != e; ++i) {
						const CXXCatchStmt* Catch = TryStmt->getHandler(i);
						if (Catch) {
							if (const Stmt* CatchBody = Catch->getHandlerBlock()) {
								MemberAccessVisitor Visitor(Mgr.getASTContext(), ContainingClass);
								Visitor.TraverseStmt(const_cast<Stmt*>(CatchBody));
								if (auto ME = Visitor.GetMemberExpr()) {
									reportBug(D, Msg, ME->getBeginLoc(), BR);
								}
							}
						}
					}
				}
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "ConstructorDestructorTryCatchChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "ConstructorDestructorTryCatchChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end of anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerConstructorDestructorTryCatchChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ConstructorDestructorTryCatchChecker>();
}

bool ento::shouldRegisterConstructorDestructorTryCatchChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ConstructorDestructorTryCatchChecker>("anzu.ConstructorDestructorTryCatchChecker", "", "");
}

#endif