#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Checkers/Taint.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class UnicodeMappingChecker : public Checker<check::PreCall, check::PostCall, check::PostStmt<Expr>> {
		mutable std::unique_ptr<BugType> BT;

		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPostStmt(const Expr* E, CheckerContext& C) const;
		bool isZero(SVal S, CheckerContext& C) const;
	};

	bool UnicodeMappingChecker::isZero(SVal S, CheckerContext& C) const {
		Optional<DefinedSVal> DSV = S.getAs<DefinedSVal>();

		if (!DSV)
			return false;

		ConstraintManager& CM = C.getConstraintManager();
		return !CM.assume(C.getState(), *DSV, true);
	}

	void UnicodeMappingChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "UnicodeMappingChecker"));

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "UnicodeMappingChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}

	void UnicodeMappingChecker::checkPostStmt(const Expr* E, CheckerContext& C) const {
	//	// For demonstration purposes, we're marking all literals as tainted.
	//	// Ideally, we'd be marking user inputs or other external data sources.
	//	if (isa<IntegerLiteral>(E)) {
	//		auto&& SV = C.getSVal(E);
	//		auto State = taint::addTaint(C.getState(), SV);
	//		C.addTransition(State);
	//	}
	}

	void UnicodeMappingChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
		if (Call.getNumArgs() < 6)
			return;

		if (const auto* FD = llvm::dyn_cast_or_null<FunctionDecl>(Call.getDecl())) {
			auto FuncName = FD->getNameAsString();

			if (FuncName == "MultiByteToWideChar" || FuncName == "WideCharToMultiByte") {
				if (auto CE = Call.getOriginExpr()) {
					// Check if output buffer pointer is NULL and its size is not 0
					if (const auto OutBuf = Call.getArgSVal(4).getAs<Loc>()) {
						if (!OutBuf) return;
						if (C.getState()->isNull(*OutBuf).isConstrainedTrue() && !isZero(Call.getArgSVal(5), C)) {
							const FunctionDecl* CFD = nullptr;
							if (auto ADC = C.getCurrentAnalysisDeclContext()) {
								CFD = dyn_cast<FunctionDecl>(ADC->getDecl());
							}
							auto ls = anzulocalization::LocaleSetting::getInstance();
							uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
							std::string Msg = ls->parseMsgs(anzulocalization::UnicodeMappingChecker, lang);
							reportBug(CFD, Msg, CE->getBeginLoc(), C.getBugReporter());
							return;
						}
					}

					// Check if input buffer and output buffer pointers are the same
					if (C.getSValBuilder().areEqual(C.getState(), Call.getArgSVal(2), Call.getArgSVal(4)).isConstrainedTrue()) {
						const FunctionDecl* CFD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							CFD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}
						reportBug(CFD, "Input and output buffer pointers are the same.", CE->getBeginLoc(), C.getBugReporter());
						return;
					}

					// Check if buffer sizes are tainted
					//if (taint::isTainted(C.getState(), Call.getArgSVal(3)) || taint::isTainted(C.getState(), Call.getArgSVal(5))) {
					//	reportBug(FD, "Buffer size argument might be tainted.", Call, C);
					//	return;
					//}
				}
			}
		}
	}

	void UnicodeMappingChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
		// TODO:
		// Transfer taint from arguments to return value if necessary
	}

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUnicodeMappingChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UnicodeMappingChecker>();
}

bool ento::shouldRegisterUnicodeMappingChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UnicodeMappingChecker>("anzu.UnicodeMappingChecker", "Checks improper use of MultiByteToWideChar and WideCharToMultiByte with taint analysis", "");
}

#endif