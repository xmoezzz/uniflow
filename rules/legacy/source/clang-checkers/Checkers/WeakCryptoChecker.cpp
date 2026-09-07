#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class WeakCryptoChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void WeakCryptoChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (!Call.getDecl())
		return;
	const auto* FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
	if (!FD)
		return;

	if (!FD->getIdentifier())
		return;

	// List of weak OpenSSL functions
	// TODO: add more
	const std::set<StringRef> WeakFunctions = {
	  "DES_set_key", "DES_set_odd_parity", "DES_ecb_encrypt",
	  "RC2_encrypt", "RC2_set_key",
	  "RC4_set_key",
	  "MD5_Init", "MD5_Update", "MD5_Final",
	  "SHA1_Init", "SHA1_Update", "SHA1_Final"
	};

	if (WeakFunctions.count(FD->getName())) {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::WeakCryptoChecker, lang);

		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}
		reportBug(FD, Msg, Call.getSourceRange().getBegin(), C.getBugReporter());
	}
}

void WeakCryptoChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "WeakCryptoChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "WeakCryptoChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerWeakCryptoChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<WeakCryptoChecker>();
}

bool ento::shouldRegisterWeakCryptoChecker(const CheckerManager& mgr) {
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
	registry.addChecker<WeakCryptoChecker>("anzu.WeakCryptoChecker", "", "");
}

#endif