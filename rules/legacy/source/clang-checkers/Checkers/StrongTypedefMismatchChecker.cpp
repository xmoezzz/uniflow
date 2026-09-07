#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <memory>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindBinaryStmtVisitor
		: public RecursiveASTVisitor<FindBinaryStmtVisitor> {
		std::list<const BinaryOperator*> StmtList;
		ASTContext& AST;

	public:
		FindBinaryStmtVisitor(ASTContext& AST) : AST(AST) {}
		const std::list<const BinaryOperator*>& getStmts() {
			return StmtList;
		}

	private:
		bool isStrongTypedefMismatch(QualType ParamType, QualType ArgType, ASTContext& Ctx) const {
			const TypedefType* ParamTypedef = ParamType->getAs<TypedefType>();
			const TypedefType* ArgTypedef = ArgType->getAs<TypedefType>();
			if (!ParamTypedef || !ArgTypedef)
				return false;

			auto ParamTD = ParamTypedef->getDecl();
			auto ArgTD = ArgTypedef->getDecl();
			if (!ParamTD || !ArgTD)
				return false;

			if (ParamTD->getName().empty() || ArgTD->getName().empty())
				return false;

			return ParamTD->getName() != ArgTD->getName();
		}

	public:
		bool VisitBinaryOperator(const BinaryOperator* BO) {
			QualType LHS = BO->getLHS()->getType();
			QualType RHS = BO->getRHS()->getType();

			if (isStrongTypedefMismatch(LHS, RHS, AST)) {
				StmtList.push_back(BO);
			}
			return true;
		}
	};

	class StrongTypedefMismatchChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		StrongTypedefMismatchChecker() {}

		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const {
			if (Mgr.getASTContext().HasSyntaxErrors()) {
				return;
			}

			if (!D)
				return;

			auto& Ctx = BR.getContext();
			auto& SM = BR.getSourceManager();
			const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);

			if (!FD || !FD->hasBody())
				return;

			FindBinaryStmtVisitor Visitor(Mgr.getASTContext());
			Visitor.TraverseDecl(const_cast<Decl*>(D));
			auto Stmts = Visitor.getStmts();
			for (auto BO : Stmts) {
				reportBug(FD, BO->getOperatorLoc(), BR);
			}
		}

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "StrongTypedefMismatchChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::StrongTypedefMismatchChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg,
				createRuleExtData(1, "StrongTypedefMismatchChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerStrongTypedefMismatchChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<StrongTypedefMismatchChecker>();
}

bool ento::shouldRegisterStrongTypedefMismatchChecker(const CheckerManager& mgr) {
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
	registry.addChecker<StrongTypedefMismatchChecker>("anzu.StrongTypedefMismatchChecker", "Detect strong typedef mismatches", "");
}

#endif