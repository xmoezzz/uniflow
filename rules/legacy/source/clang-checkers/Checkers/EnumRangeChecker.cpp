#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "../Utils.h"
#include <unordered_map>

using namespace clang;
using namespace ento;

namespace {

	class EnumRangeChecker : public Checker<check::PreStmt<CastExpr>> {
		mutable std::unique_ptr<BugType> BT;
		mutable std::unordered_map<const EnumDecl*, std::pair<int64_t, int64_t>> EnumRanges;

	public:
		void checkPreStmt(const CastExpr* CE, CheckerContext& C) const;
		bool getEnumRange(const EnumDecl* ED, int64_t &MinValue, int64_t &MaxValue) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void EnumRangeChecker::checkPreStmt(const CastExpr* CE, CheckerContext& C) const {
	if (CE->getSubExpr()->getType() == CE->getType())
		return;

	auto TypePtr = CE->getType().getTypePtr();
	if (auto ET = dyn_cast<ElaboratedType>(TypePtr)) {
		TypePtr = ET->getNamedType().getTypePtr();
	}
	if (!TypePtr)
		return;

	const EnumType* ET = dyn_cast_or_null<EnumType>(TypePtr);
	if (!ET)
		return;

	const EnumDecl* ED = ET->getDecl();
	if (!ED)
		return;

	if (ED->isScoped())
		return;

	auto Val = C.getSVal(CE->getSubExpr());
	auto NonLocVal = Val.getAs<NonLoc>();
	if (!NonLocVal)
		return;

	int64_t MinValue = 0;
	int64_t MaxValue = 0;
	if (!getEnumRange(ED, MinValue, MaxValue))
		return;

	auto& CM = C.getConstraintManager();
	auto& State = C.getState();

	llvm::APInt I1(64, MinValue, true);
	llvm::APSInt N1(I1, false);
	llvm::APInt I2(64, MaxValue, true);
	llvm::APSInt N2(I2, false);

	ProgramStateRef stateTrue, stateFalse;
	std::tie(stateTrue, stateFalse) = CM.assumeInclusiveRangeDual(State, *NonLocVal, N1, N2);
	if (stateFalse) {
		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}

		reportBug(FD, CE->getBeginLoc(), C.getBugReporter());
	}
}

bool EnumRangeChecker::getEnumRange(const EnumDecl* ED, int64_t& MinValue, int64_t& MaxValue) const {
	if (!ED)
		return false;

	auto It = EnumRanges.find(ED);
	if (It != EnumRanges.end()) {
		MinValue = It->second.first;
		MaxValue = It->second.second;
		return true;
	}

	bool First = true;
	for (const EnumConstantDecl* ECD : ED->enumerators()) {
		auto V = ECD->getInitVal().getExtValue();
		if (First) {
			First = false;
			MinValue = V;
			MaxValue = V;
		}
		else {
			if (V < MinValue) {
				MinValue = V;
			}
			if (V > MaxValue) {
				MaxValue = V;
			}
		}
	}

	if (First)
		return false;

	EnumRanges[ED] = std::make_pair(MinValue, MaxValue);

	return true;
}

void EnumRangeChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(this, "EnumRangeChecker"));
	}

	// Report the issue
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::EnumRangeChecker, lang);        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "EnumRangeChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerEnumRangeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<EnumRangeChecker>();
}

bool ento::shouldRegisterEnumRangeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<EnumRangeChecker>("anzu.EnumRangeChecker", "", "");
}

#endif