#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class StrongTypedefArgumentMismatchChecker : public Checker<check::PreStmt<CallExpr>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		StrongTypedefArgumentMismatchChecker() {}

		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
			const FunctionDecl* FD = CE->getDirectCallee();
			if (!FD)
				return;

			for (unsigned i = 0; i < CE->getNumArgs() && i < FD->getNumParams(); ++i) {
				auto PD = FD->getParamDecl(i);
				if (!PD)
					continue;

				auto Arg = CE->getArg(i);
				if (!Arg)
					continue;

				QualType ParamType = PD->getType();
				QualType ArgType = Arg->getType();
				if (isStrongTypedefMismatch(ParamType, ArgType, C.getASTContext())) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}
					reportBug(FD, Arg->getBeginLoc(), C.getBugReporter());
				}
			}
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

		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "StrongTypedefArgumentMismatchChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::StrongTypedefArgumentMismatchChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg,
				createRuleExtData(1, "StrongTypedefArgumentMismatchChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}

	};
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerStrongTypedefArgumentMismatchChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<StrongTypedefArgumentMismatchChecker>();
}

bool ento::shouldRegisterStrongTypedefArgumentMismatchChecker(const CheckerManager& mgr) {
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
	registry.addChecker<StrongTypedefArgumentMismatchChecker>("anzu.StrongTypedefArgumentMismatchChecker", "Detect strong typedef argument mismatches", "");
}

#endif