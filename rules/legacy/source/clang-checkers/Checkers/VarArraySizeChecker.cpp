#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

#include <set>

using namespace clang;
using namespace clang::ento;

namespace {
	class VarArraySizeChecker : public Checker<check::PreStmt<DeclStmt>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const DeclStmt* DS, CheckerContext& C) const;
		bool isValidVAT(const VarDecl* VD, CheckerContext& C) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void VarArraySizeChecker::checkPreStmt(const DeclStmt* DS, CheckerContext& C) const {
	if (DS) {
		for (auto D : DS->decls()) {
			if (auto VD = dyn_cast<VarDecl>(D)) {
				if (!isValidVAT(VD, C)) {
					reportBug(findFunctionDecl(VD), VD->getBeginLoc(), C.getBugReporter());
				}
			}
		}
	}
}

bool VarArraySizeChecker::isValidVAT(const VarDecl* VD, CheckerContext& C) const {
	if (!VD)
		return true;

	if (auto VAT = dyn_cast<VariableArrayType>(VD->getType())) {
		auto State = C.getState();
		auto SizeVal = State->getSVal(VAT->getSizeExpr(), C.getLocationContext());
		if (auto NonLocSizeVal = dyn_cast<NonLoc>(SizeVal)) {
			auto& CM = State->getConstraintManager();
			auto InvalidSize = C.getSValBuilder().makeIntVal(0x7FFFFFFF, C.getSValBuilder().getArrayIndexType());
			if (auto NonLocInvalidSize = dyn_cast<NonLoc>(InvalidSize)) {
				SVal CV = C.getSValBuilder().evalBinOpNN(C.getState(), BO_EQ, *NonLocSizeVal, *NonLocInvalidSize, C.getSValBuilder().getConditionType());
				if (auto DCV = dyn_cast<DefinedSVal>(CV)) {
					ProgramStateRef stateTrue, stateFalse;
					std::tie(stateTrue, stateFalse) = C.getState()->assume(*DCV);
					if (stateTrue) {
						return false;
					}
				}
			}
		}
	}

	return true;
}

void VarArraySizeChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "CharArrayInitChecker"));
	}
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::VarArraySizeChecker, lang);

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "VarArraySizeChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerVarArraySizeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<VarArraySizeChecker>();
}

bool ento::shouldRegisterVarArraySizeChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::C);
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
	registry.addChecker<VarArraySizeChecker>("anzu.VarArraySizeChecker", "", "");
}

#endif