#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class CMemFunctionsInCppChecker : public Checker<check::PreCall, check::PreStmt<ExplicitCastExpr>> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPreStmt(const ExplicitCastExpr* CE, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void CMemFunctionsInCppChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (const auto* FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl())) {
		auto FName = FD->getNameAsString();

		if (Call.getNumArgs() >= 1 && FName == "free") {
			auto Arg = Call.getArgExpr(0);
			if (!Arg)
				return;

			if (auto OriginPT = Arg->IgnoreParenCasts()->getType().getCanonicalType()->getAs<PointerType>()) {
				if (auto CXXRD = OriginPT->getPointeeType()->getAsCXXRecordDecl()) {
					if (CXXRD->isClass()) {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}
						reportBug(FD, Arg->getBeginLoc(), C.getBugReporter());
					}
				}
			}
		}
	}
}

void CMemFunctionsInCppChecker::checkPreStmt(const ExplicitCastExpr* ECE, CheckerContext& C) const {
	if (auto CE = dyn_cast<CallExpr>(ECE->getSubExpr()->IgnoreParenCasts())) {
		if (auto FD = CE->getDirectCallee()) {
			if (FD->isGlobal() && CE->getNumArgs() >= 1) {
				auto FName = FD->getNameAsString();
				if (FName == "malloc" || FName == "calloc" || FName == "realloc") {
					if (auto OriginPT = ECE->getType().getCanonicalType()->getAs<PointerType>()) {
						if (auto CXXRD = OriginPT->getPointeeType()->getAsCXXRecordDecl()) {
							if (CXXRD->isClass()) {
								const FunctionDecl* FD = nullptr;
								if (auto ADC = C.getCurrentAnalysisDeclContext()) {
									FD = dyn_cast<FunctionDecl>(ADC->getDecl());
								}
								reportBug(FD, CE->getBeginLoc(), C.getBugReporter());
							}
						}
					}
				}
			}
		}
	}
}

void CMemFunctionsInCppChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(this, "CMemFunctionsInCppChecker"));
	}

	// Report the issue  
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CMemFunctionsInCppChecker, lang);      
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "MemFunctionsInCppChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCMemFunctionsInCppChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CMemFunctionsInCppChecker>();
}

bool ento::shouldRegisterCMemFunctionsInCppChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CMemFunctionsInCppChecker>("anzu.CMemFunctionsInCppChecker", "", "");
}

#endif