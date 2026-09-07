#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class MultipleRelatedFunctionCallsChecker : public Checker<check::PreStmt<CallExpr>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void MultipleRelatedFunctionCallsChecker::checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
	unsigned int relatedFunctionCalls = 0;

	SourceLocation BugLoc;
	for (const auto* Arg : CE->arguments()) {
		if (const CallExpr* Call = llvm::dyn_cast_or_null<CallExpr>(Arg)) {
			if (auto FD = Call->getDirectCallee()) {
				if (auto MD = dyn_cast<CXXMethodDecl>(FD)) {
					if (!MD->isConst()) {
						relatedFunctionCalls++;
					}
				}
				else if (isa<ObjCMethodDecl>(FD)) {
					relatedFunctionCalls++;
				}
			}

			if (relatedFunctionCalls > 1) {
				BugLoc = Call->getBeginLoc();
				break;
			}
		}
	}

	if (relatedFunctionCalls > 1) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::MultipleRelatedFunctionCallsChecker, lang);
		reportBug(FD, Msg, BugLoc, C.getBugReporter());
	}
}

void MultipleRelatedFunctionCallsChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "MultipleRelatedFunctionCallsChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "MultipleRelatedFunctionCallsChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMultipleRelatedFunctionCallsChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MultipleRelatedFunctionCallsChecker>();
}

bool ento::shouldRegisterMultipleRelatedFunctionCallsChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MultipleRelatedFunctionCallsChecker>("anzu.MultipleRelatedFunctionCallsChecker", "Detects multiple related function calls in the same expression", "");
}

#endif