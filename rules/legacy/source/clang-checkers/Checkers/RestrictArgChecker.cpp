#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include <vector>
#include "../Utils.h"
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {

	class RestrictArgChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;

	private:
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void RestrictArgChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	auto D = Call.getDecl();
	if (!D)
		return;

	auto FD = dyn_cast<FunctionDecl>(D);
	if (!FD)
		return;

	const FunctionDecl* CFD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		CFD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::RestrictArgChecker, lang);

	std::unordered_set<const void*> SymSets;
	int Index = 0;
	for (auto PVD : FD->parameters()) {
		auto ArgExpr = Call.getArgExpr(Index);
		auto ArgVal = Call.getArgSVal(Index);
		++Index;

		if (!ArgExpr)
			continue;

		if (!PVD->getType().isRestrictQualified())
			continue;

		if (auto Sym = ArgVal.getAsSymbol()) {
			if (SymSets.find(Sym) != SymSets.end()) {
				std::string arg = ToString(ArgExpr);
				std::string Msg = std::vformat(fmt, std::make_format_args(arg));
				reportBug(CFD, Msg, ArgExpr->getBeginLoc(), C.getBugReporter());
				return;
			}
			else {
				SymSets.insert(Sym);
			}

			for (SymExpr::symbol_iterator SI = Sym->symbol_begin(),
				SE = Sym->symbol_end();
				SI != SE; ++SI) {
				if (const auto* SD = dyn_cast<SymbolDerived>(*SI)) {
					if (const auto* ER = dyn_cast<ElementRegion>(SD->getRegion())) {
						if (SymbolRef ParentSym = SD->getParentSymbol()) {
							if (SymSets.find(ParentSym) != SymSets.end()) {
								std::string arg = ToString(ArgExpr);
								std::string Msg = std::vformat(fmt, std::make_format_args(arg));
								reportBug(CFD, Msg, ArgExpr->getBeginLoc(), C.getBugReporter());
								return;
							}
							else {
								SymSets.insert(ParentSym);
							}
						}
					}
				}
			}
		}
		else if (auto Region = ArgVal.getAsRegion()) {
			if (SymSets.find(Region) != SymSets.end()) {
				std::string arg = ToString(ArgExpr);
				std::string Msg = std::vformat(fmt, std::make_format_args(arg));
				reportBug(CFD, Msg, ArgExpr->getBeginLoc(), C.getBugReporter());
				return;
			}
			else {
				SymSets.insert(Region);
			}
		}
	}
}

void RestrictArgChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "RestrictArgChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "RestrictArgChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerRestrictArgChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<RestrictArgChecker>();
}

bool ento::shouldRegisterRestrictArgChecker(const CheckerManager& mgr) {
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
	registry.addChecker<RestrictArgChecker>("anzu.RestrictArgChecker", "", "");
}

#endif
