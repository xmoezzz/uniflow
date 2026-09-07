#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class FindCharCmpVisitor
		: public RecursiveASTVisitor<FindCharCmpVisitor> {
		std::list<const BinaryOperator*> ExprList;

	public:
		const std::list<const BinaryOperator*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitBinaryOperator(const BinaryOperator* BO) {
			if (BO->getOpcode() >= BinaryOperator::Opcode::BO_LT &&
				BO->getOpcode() <= BinaryOperator::Opcode::BO_GE) {
				if (isa<CharacterLiteral>(BO->getLHS()->IgnoreParenCasts())) {
					ExprList.push_back(BO);
				}
				else if (isa<CharacterLiteral>(BO->getRHS()->IgnoreParenCasts())) {
					ExprList.push_back(BO);
				}
			}
			return true;
		}
	};

	class CharCondChecker : public Checker<check::BranchCondition> {
		mutable std::unique_ptr<BuiltinBug> BT;
	public:
		void checkBranchCondition(const Stmt* Condition, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void CharCondChecker::checkBranchCondition(const Stmt* Condition, CheckerContext& C) const {
	if (Condition) {
		FindCharCmpVisitor Visitor;
		Visitor.TraverseStmt(const_cast<Stmt*>(Condition));
		auto Exprs = Visitor.getExprs();
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::CharCondChecker, lang);
		for (auto BO : Exprs) {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}

			reportBug(FD, Msg, BO->getOperatorLoc(), C.getBugReporter());
		}
	}
}

void CharCondChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "CharCondChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CharCondChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCharCondChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CharCondChecker>();
}

bool ento::shouldRegisterCharCondChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CharCondChecker>("anzu.CharCondChecker", "", "");
}

#endif