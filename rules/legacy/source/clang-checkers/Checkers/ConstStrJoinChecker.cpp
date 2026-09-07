#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class ConstStrJoinChecker : public Checker<check::ASTDecl<VarDecl>, check::PreStmt<BinaryOperator>> {
		mutable std::unique_ptr<BuiltinBug> BT;
	public:
		void checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const;
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		bool isValidStringLiteral(ASTContext &AST, const Expr* E) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void ConstStrJoinChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const {
	if (auto Init = VD->getInit()) {
		if (isValidStringLiteral(mgr.getASTContext(), Init))
			return;
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::ConstStrJoinChecker, lang);
		reportBug(findFunctionDecl(VD), Msg, Init->getBeginLoc(), BR);
	}
}

void ConstStrJoinChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (B->getOpcode() != BO_Assign) {
		return;
	}
	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}
	const Expr* LHS = B->getLHS();
	const Expr* RHS = B->getRHS()->IgnoreParenImpCasts();

	if (isValidStringLiteral(C.getASTContext(), RHS))
		return;

	reportBug(FD, "Do not concatenate different type of string literals", RHS->getBeginLoc(), C.getBugReporter());
}

bool ConstStrJoinChecker::isValidStringLiteral(ASTContext& AST, const Expr* E) const {
	if (!E)
		return true;

	E = E->IgnoreParenCasts();
	if (!isa<StringLiteral>(E))
		return true;

	auto Data = getSourceCode(AST, E->getBeginLoc(), E->getEndLoc());
	bool HasQuota = false;
	bool HasDoubleQuota = false;
	char PreChar = 0;
	bool IsEnd = false;
	for (int i = 0; i < Data.size(); ++i) {
		auto C = Data[i];
		if (C == '"') {
			if (i == 0) {
				HasQuota = true;
				IsEnd = true;
			}
			else if (PreChar == 'L') {
				HasDoubleQuota = true;
				IsEnd = true;
			}
			else if (PreChar != '\\') {
				if (IsEnd) {
					IsEnd = false;
				}
				else {
					HasQuota = true;
					IsEnd = true;
				}
			}
		}

		// todo: Ignore Comment
		if (PreChar == '/') {
			if (C == '*' || C == '/') {
				return true;
			}
		}

		PreChar = C;
	}

	if (!HasQuota || !HasDoubleQuota)
		return true;

	return false;
}

void ConstStrJoinChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "ConstStrJoinChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ConstStrJoinChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerConstStrJoinChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ConstStrJoinChecker>();
}

bool ento::shouldRegisterConstStrJoinChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ConstStrJoinChecker>("anzu.ConstStrJoinChecker", "", "");
}

#endif