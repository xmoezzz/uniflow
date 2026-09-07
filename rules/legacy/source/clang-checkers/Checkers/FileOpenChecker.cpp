#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {
	static const std::unordered_set<std::string> ValidModes = {
		"r", "w", "wx", "a", "rb", "wb", "wbx", "ab",
		"r+", "w+", "w+x", "a+", "r+b", "rb+", "w+b", "wb+", "w+bx", "wb+x", "a+b", "ab+" };

	class FileOpenChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;

	private:
		bool ValidModeString(const StringRef& ModeStr) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void FileOpenChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
		const auto* FD = dyn_cast_or_null<FunctionDecl>(Call.getDecl());
		if (!FD)
			return;

		auto Name = FD->getQualifiedNameAsString();

		int ModeStrIndex = -1;
		if (Name == "fopen" || Name == "wfopen") {
			ModeStrIndex = 1;
		}
		else if (Name == "fopen_s" || Name == "wfopen_s") {
			ModeStrIndex = 2;
		}
		else {
			return;
		}

		if (Call.getNumArgs() < ModeStrIndex + 1)
			return;

		const Expr* ModeStrExpr = Call.getArgExpr(ModeStrIndex);
		if (!ModeStrExpr)
			return;

		const StringLiteral* StrLiteral = llvm::dyn_cast_or_null<StringLiteral>(ModeStrExpr->IgnoreParenCasts());
		if (!StrLiteral)
			return;

		if (StrLiteral->getCharByteWidth() != 1)
			return;

		StringRef ModeStr = StrLiteral->getString();
		if (!ValidModeString(ModeStr)) {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}

			reportBug(FD, StrLiteral->getBeginLoc(), C.getBugReporter());
		}
	}

	bool FileOpenChecker::ValidModeString(const StringRef& ModeStr) const {
		auto Mode = ModeStr.str();
		if (Mode.empty())
			return true;

		return ValidModes.find(Mode) != ValidModes.end();
	}

	void FileOpenChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "FileOpenChecker"));

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::FileOpenChecker, lang);          
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "FileOpenChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFileOpenChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FileOpenChecker>();
}

bool ento::shouldRegisterFileOpenChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FileOpenChecker>("anzu.FileOpenChecker", "", "");
}

#endif