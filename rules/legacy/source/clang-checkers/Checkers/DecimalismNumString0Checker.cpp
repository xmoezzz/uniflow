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

	class DecimalismNumString0Checker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			FindIntegerLiteralVisitor Visitor(Mgr.getASTContext());
			Visitor.TraverseDecl(const_cast<Decl*>(D));
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::DecimalismNumString0Checker, lang);
			auto& Stmts = Visitor.getStmts();
			for (auto IL : Stmts) {
				reportBug(D, Msg, IL->getBeginLoc(), BR);
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "DecimalismNumString0Checker"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "DecimalismNumString0Checker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerDecimalismNumString0Checker(CheckerManager& Mgr) {
	Mgr.registerChecker<DecimalismNumString0Checker>();
}

bool ento::shouldRegisterDecimalismNumString0Checker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::C);
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
	registry.addChecker<DecimalismNumString0Checker>("anzu.DecimalismNumString0Checker", "When specifying a decimal number, do not start the integer constant with 0", "");
}

#endif