#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindIntegerLiteralVisitor
		: public RecursiveASTVisitor<FindIntegerLiteralVisitor> {
		ASTContext& AST;
		std::list<const IntegerLiteral*> StmtList;

	public:
		FindIntegerLiteralVisitor(ASTContext& AST) : AST(AST) {}
		const std::list<const IntegerLiteral*>& getStmts() {
			return StmtList;
		}

	public:
		bool VisitIntegerLiteral(const IntegerLiteral* IL) {
			if (auto BT = dyn_cast<BuiltinType>(IL->getType().getTypePtr())) {
				if (BT->getKind() == BuiltinType::Kind::Long ||
					BT->getKind() == BuiltinType::Kind::LongLong) {
					auto Data = getSourceCode(AST, IL->getBeginLoc(), IL->getEndLoc());
					if (Data.find('l') != std::string::npos) {
						StmtList.push_back(IL);
					}
				}
			}
			return true;
		}
	};

	class LongNumStringlLChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			FindIntegerLiteralVisitor Visitor(Mgr.getASTContext());
			Visitor.TraverseDecl(const_cast<Decl*>(D));
			auto& Stmts = Visitor.getStmts();
			for (auto IL : Stmts) {
				reportBug(D, "Use 'L' instead of 'l' to indicate a long value.", IL->getBeginLoc(), BR);
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "LongNumStringlLChecker"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "LongNumStringlLChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerLongNumStringlLChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<LongNumStringlLChecker>();
}

bool ento::shouldRegisterLongNumStringlLChecker(const CheckerManager& mgr) {
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
	registry.addChecker<LongNumStringlLChecker>("anzu.LongNumStringlLChecker", "Use 'L' instead of 'l' to indicate a long value.", "");
}

#endif