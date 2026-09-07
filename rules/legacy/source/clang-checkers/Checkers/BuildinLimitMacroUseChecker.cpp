#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {
	class BuildinLimitMacroUseChecker : public Checker<check::BranchCondition> {
		mutable std::unique_ptr<BuiltinBug> BT;
		std::unordered_set<std::string> Macros = {
			"SCHAR_MAX",
			"SHRT_MAX",
			"INT_MAX",
			"LONG_MAX",
			"SCHAR_MIN",
			"SHRT_MIN",
			"INT_MIN",
			"LONG_MIN",
			"UCHAR_MAX",
			"USHRT_MAX",
			"UINT_MAX",
			"ULONG_MAX",
			"MB_LEN_MAX",
			"LLONG_MAX",
			"LLONG_MIN",
			"ULLONG_MAX",
			"LONG_LONG_MAX",
			"LONG_LONG_MIN",
			"ULONG_LONG_MAX",
			"CHAR_MAX",
			"BOOL_WIDTH",
			"CHAR_WIDTH",
			"SCHAR_WIDTH",
			"UCHAR_WIDTH",
			"USHRT_WIDTH",
			"SHRT_WIDTH",
			"UINT_WIDTH",
			"INT_WIDTH",
			"ULONG_WIDTH",
			"LONG_WIDTH",
			"ULLONG_WIDTH",
			"LLONG_WIDTH",
		};
	public:
		void checkBranchCondition(const Stmt* S, CheckerContext& C) const {
			checkBuildinMacroCond(dyn_cast<Expr>(S), C);
		}

	private:
		bool checkBuildinMacroCond(const Expr* E, CheckerContext& C) const {
			if (!E)
				return false;

			auto BO = dyn_cast<BinaryOperator>(E->IgnoreParenCasts());
			if (!BO)
				return false;

			auto LHS = BO->getLHS();
			auto RHS = BO->getRHS();
			if (!BO->isRelationalOp())
				return false;
			
			if (auto IL = dyn_cast<IntegerLiteral>(LHS)) {
				if (C.getSourceManager().isInSystemMacro(IL->getLocation())) {
					auto Data = getSourceCode(C.getASTContext(), IL->getBeginLoc(), IL->getEndLoc());
					if (Macros.find(Data) != Macros.end()) {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}

						reportBug(FD, IL->getLocation(), C.getBugReporter());
						return true;
					}
				}
			}

			if (auto IL = dyn_cast<IntegerLiteral>(RHS)) {
				if (C.getSourceManager().isInSystemMacro(IL->getLocation())) {
					auto Data = getSourceCode(C.getASTContext(), IL->getBeginLoc(), IL->getEndLoc());
					if (Macros.find(Data) != Macros.end()) {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}

						reportBug(FD, IL->getLocation(), C.getBugReporter());
						return true;
					}
				}
			}

			return checkBuildinMacroCond(LHS, C) || checkBuildinMacroCond(RHS, C);
		}

		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "BuildinLimitMacroUseChecker"));

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::BuildinLimitMacroUseChecker, lang);
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "BuildinLimitMacroUseChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBuildinLimitMacroUseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BuildinLimitMacroUseChecker>();
}

bool ento::shouldRegisterBuildinLimitMacroUseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BuildinLimitMacroUseChecker>("anzu.BuildinLimitMacroUseChecker", "Dsiable using built-in limit value macros", "");
}

#endif