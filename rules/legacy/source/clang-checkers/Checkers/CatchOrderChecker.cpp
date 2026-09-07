#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/StmtCXX.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class CatchOrderChecker : public Checker<check::ASTCodeBody> {
	private:
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;

		bool isDerivedFrom(const Type* Derived,
			const Type* Base,
			ASTContext& Context) const;

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
} // namespace

void CatchOrderChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
	BugReporter& BR) const {
	const auto* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);
	if (!FD || !FD->getBody())
		return;

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CatchOrderChecker, lang);
	for (const Stmt* S : FD->getBody()->children()) {
		const auto* TS = llvm::dyn_cast_or_null<CXXTryStmt>(S);
		if (!TS)
			continue;

		const Type* PrevType = nullptr;
		auto Num = TS->getNumHandlers();
		for (unsigned int i = 0; i < Num; i++) {
			const auto* CS = TS->getHandler(i);
			if (!CS)
				continue;

			const VarDecl* CatchVar = CS->getExceptionDecl();
			if (!CatchVar)
				continue;

			const QualType& CurrentType = CatchVar->getType();
			if (PrevType && isDerivedFrom(CurrentType.getTypePtr(), PrevType, Mgr.getASTContext())) {
				reportBug(D, Msg, CS->getBeginLoc(), BR);
			}

			PrevType = CurrentType.getTypePtr();
		}
	}
}

bool CatchOrderChecker::isDerivedFrom(const Type* Derived,
	const Type* Base,
	ASTContext& Context) const {
	if (!Derived || !Base)
		return false;

	const CXXRecordDecl* BaseRD = nullptr;
	if (auto BT = dyn_cast<ReferenceType>(Base)) {
		BaseRD = Context.getCanonicalType(BT->getPointeeType()).getTypePtr()->getAsCXXRecordDecl();
	}
	else if (auto BT = dyn_cast<PointerType>(Base)) {
		BaseRD = Context.getCanonicalType(BT->getPointeeType()).getTypePtr()->getAsCXXRecordDecl();
	}
	else {
		BaseRD = Context.getCanonicalType(Base)->getAsCXXRecordDecl();
	}

	const CXXRecordDecl* DerivedRD = nullptr;
	if (auto BT = dyn_cast<ReferenceType>(Derived)) {
		DerivedRD = Context.getCanonicalType(BT->getPointeeType()).getTypePtr()->getAsCXXRecordDecl();
	}
	else if (auto BT = dyn_cast<PointerType>(Derived)) {
		DerivedRD = Context.getCanonicalType(BT->getPointeeType()).getTypePtr()->getAsCXXRecordDecl();
	}
	else {
		DerivedRD = Context.getCanonicalType(Derived)->getAsCXXRecordDecl();
	}

	if (!BaseRD || !DerivedRD)
		return false;

	return DerivedRD->isDerivedFrom(BaseRD);
}

void CatchOrderChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "CatchOrderChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CatchOrderChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCatchOrderChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CatchOrderChecker>();
}

bool ento::shouldRegisterCatchOrderChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CatchOrderChecker>("anzu.CatchOrderChecker", "", "");
}

#endif