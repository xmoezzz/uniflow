#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class MallocResultExplictCastChecker : public Checker< check::PreStmt<BinaryOperator> > {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void MallocResultExplictCastChecker::checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const {
		auto RHS = BO->getRHS()->IgnoreParenImpCasts();
		if (auto CE = dyn_cast<CallExpr>(RHS)) {
			if (auto FD = CE->getDirectCallee()) {
				auto Name = FD->getQualifiedNameAsString();
				if (Name == "malloc" ||
					Name == "aligned_alloc" ||
					Name == "calloc" ||
					Name == "realloc") {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}
					auto ls = anzulocalization::LocaleSetting::getInstance();
					uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
					std::string Msg = ls->parseMsgs(anzulocalization::MallocResultExplictCastChecker, lang);
					reportBug(FD,
						Msg,
						CE->getBeginLoc(),
						C.getBugReporter());
				}
			}
		}
	}

	void MallocResultExplictCastChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "MallocResultExplictCastChecker"));

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "MallocResultExplictCastChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMallocResultExplictCastChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MallocResultExplictCastChecker>();
}

bool ento::shouldRegisterMallocResultExplictCastChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MallocResultExplictCastChecker>("anzu.MallocResultExplictCastChecker", "", "");
}

#endif
