#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class ManualMemoryManagementChecker : public Checker<check::PostCall> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
} // end anonymous namespace

void ManualMemoryManagementChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
	// Check for malloc and free calls.
	if (const auto* FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl())) {
		auto FName = FD->getNameAsString();
		if (FName == "malloc") {
			// Check if the allocated type has non-trivial constructors.
			if (const auto* CE = Call.getOriginExpr()) {
				if (const auto* RD = CE->getType()->getAsCXXRecordDecl()) {
					if (RD->hasNonTrivialDefaultConstructor()) {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}
						auto ls = anzulocalization::LocaleSetting::getInstance();
						uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
						std::string Msg = ls->parseMsgs(anzulocalization::ManualMemoryManagementChecker, lang);
						reportBug(FD, Msg, CE->getBeginLoc(), C.getBugReporter());
						return;
					}
				}
			}
		}
		else if (FName == "free") {
			// Similarly, check for non-trivial destructors when using free.
			if (const auto* CE = Call.getOriginExpr()) {
				if (const auto* RD = CE->getType()->getAsCXXRecordDecl()) {
					if (RD->hasNonTrivialDestructor()) {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}
						reportBug(FD, "Memory deallocated for an object with non-trivial destructor but destructor is not called.", CE->getBeginLoc(), C.getBugReporter());
						return;
					}
				}
			}
		}
	}
}

void ManualMemoryManagementChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(this, "ManualMemoryManagementChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ManualMemoryManagementChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerManualMemoryManagementChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ManualMemoryManagementChecker>();
}

bool ento::shouldRegisterManualMemoryManagementChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ManualMemoryManagementChecker>("anzu.ManualMemoryManagementChecker", "", "");
}

#endif