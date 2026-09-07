#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/SVals.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class NullCharTraitsChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;

	private:
		void reportBug(std::string& Msg, CheckerContext& C) const;
	};
} // end of anonymous namespace

void NullCharTraitsChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (Call.getNumArgs() == 0)
		return;

	if (auto D = Call.getDecl()) {
		if (const CXXMethodDecl* MD = dyn_cast_or_null<CXXMethodDecl>(D)) {
			if (auto PD = MD->getParent()) {
				if (MD->getNameAsString() == "length" && PD->getQualifiedNameAsString() == "std::char_traits") {
					if (const auto ArgSVal = dyn_cast_or_null<DefinedSVal>(Call.getArgSVal(0))) {
						ProgramStateRef State = C.getState();
						ConditionTruthVal T = State->isNull(*ArgSVal);
						if (T.isConstrainedTrue()) {
							auto ls = anzulocalization::LocaleSetting::getInstance();
							uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
							std::string Msg = ls->parseMsgs(anzulocalization::NullCharTraitsChecker, lang);
							reportBug(Msg, C);
							return;
						}
					}
				}
			}
		}
	}
}

void NullCharTraitsChecker::reportBug(std::string& Msg, CheckerContext& C) const {
	if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
		if (!BT)
			BT.reset(new BuiltinBug(this, "NullCharTraitsChecker"));

		auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "NullCharTraitsChecker"), Msg, N);
		C.emitReport(std::move(R));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerNullCharTraitsChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<NullCharTraitsChecker>();
	}

bool ento::shouldRegisterNullCharTraitsChecker(const CheckerManager& mgr) {
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
	registry.addChecker<NullCharTraitsChecker>("anzu.NullCharTraitsChecker", "Do not pass null pointer to char_traits::length", "");
}

#endif