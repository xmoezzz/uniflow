#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class INT05CPPChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void INT05CPPChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(Call.getDecl());
	if (!FD)
		return;

	if (Call.getNumArgs() == 0)
		return;

	auto FName = FD->getQualifiedNameAsString();
	if (FName == "scanf" || FName == "scanf_s") {
		auto Arg = Call.getArgExpr(0);
		if (!Arg)
			return;

		const StringLiteral* FormatStrLit = llvm::dyn_cast_or_null<StringLiteral>(Arg->IgnoreParenCasts());
		if (!FormatStrLit)
			return;

		if (FormatStrLit->getCharByteWidth() != 1)
			return;

		StringRef FormatStr = FormatStrLit->getString();
		if (FormatStr.contains("%d") || FormatStr.contains("%f") || FormatStr.contains("%lf") || FormatStr.contains("%i") || FormatStr.contains("%u")) {
			reportBug(FD, FormatStrLit->getBeginLoc(), C.getBugReporter());
		}
	}
}

void INT05CPPChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "INT05CPPChecker"));

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::INT05CPPChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "INT05CPPChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerINT05CPPChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<INT05CPPChecker>();
}

bool ento::shouldRegisterINT05CPPChecker(const CheckerManager& mgr) {
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
	registry.addChecker<INT05CPPChecker>("anzu.INT05CPPChecker", "", "");
}

#endif