#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class HardcodedCryptoKeyChecker : public Checker<check::PreStmt<CallExpr>> {
		mutable std::unique_ptr<BugType> BT;
		// Define a mapping where the key is the function name and the value is the argument index that receives the encryption key.
		std::map<StringRef, unsigned> CryptoKeyFunctions = {
			{"DES_set_key", 0},
			{"AES_set_encrypt_key", 0},
			{"AES_set_decrypt_key", 0},
			{"EVP_BytesToKey", 2}
			// ... other functions and corresponding argument indices ...
		};

	public:
		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void HardcodedCryptoKeyChecker::checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
		const FunctionDecl* FD = CE->getDirectCallee();
		if (!FD) return;
		if (!FD->getIdentifier()) return;

		StringRef FName = FD->getName();

		auto it = CryptoKeyFunctions.find(FName);
		if (it == CryptoKeyFunctions.end()) return;

		unsigned keyArgIndex = it->second;
		if (keyArgIndex >= CE->getNumArgs()) return;  // Check for index validity

		const Expr* Arg = CE->getArg(keyArgIndex)->IgnoreParenCasts();
		if (isa<StringLiteral>(Arg)) {
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::HardcodedCryptoKeyChecker, lang);

			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, Msg, Arg->getBeginLoc(), C.getBugReporter());
		}
	}

	void HardcodedCryptoKeyChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "HardcodedCryptoKeyChecker"));

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "HardcodedCryptoKeyChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerHardcodedCryptoKeyChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<HardcodedCryptoKeyChecker>();
}

bool ento::shouldRegisterHardcodedCryptoKeyChecker(const CheckerManager& mgr) {
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
	registry.addChecker<HardcodedCryptoKeyChecker>("anzu.HardcodedCryptoKeyChecker", "", "");
}

#endif