#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Decl.h"
#include "../Utils.h"
#include <unordered_map>

using namespace clang;
using namespace ento;

namespace {
	std::unordered_map<std::string, unsigned int> FunctionMap =
	{
		{"isalnum", 0},
		{"isalpha", 0},
		{"isascii", 0},
		{"isblank", 0},
		{"iscntrl", 0},
		{"isdigit", 0},
		{"isgraph", 0},
		{"islower", 0},
		{"isprint", 0},
		{"ispunct", 0},
		{"isspace", 0},
		{"isupper", 0},
		{"isxdigit", 0},
		{"toascii", 0},
		{"toupper", 0},
		{"tolower", 0},
	};

	class CtypeFuncUseChecker : public Checker<check::PreStmt<CallExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}


void CtypeFuncUseChecker::checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
	const FunctionDecl* FD = C.getCalleeDecl(CE);
	if (!FD)
		return;

	if (!FD->isGlobal())
		return;

	auto Name = FD->getQualifiedNameAsString();
	auto It = FunctionMap.find(Name);
	if (It == FunctionMap.end())
		return;

	if (It->second >= CE->getNumArgs())
		return;

	auto Arg = CE->getArg(It->second);
	if (!Arg)
		return;

	Arg = Arg->IgnoreParenImpCasts();
	if (const Type* Ty = Arg->getType().getTypePtr()) {
		if (const auto* BuildinT = dyn_cast<BuiltinType>(Ty)) {
			if (BuildinT->getKind() == BuiltinType::Char_S) {

				const FunctionDecl* CFD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					CFD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::CtypeFuncUseChecker, lang);
				reportBug(CFD, Msg, Arg->getBeginLoc(), C.getBugReporter());
			}
		}
	}
}

void CtypeFuncUseChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "CtypeFuncUseChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CtypeFuncUseChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCtypeFuncUseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CtypeFuncUseChecker>();
}

bool ento::shouldRegisterCtypeFuncUseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CtypeFuncUseChecker>("anzu.CtypeFuncUseChecker", "Pass parameters that cannot be represented as unsigned characters to character processing functions", "");
}

#endif
