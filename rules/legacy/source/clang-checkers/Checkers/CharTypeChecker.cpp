#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class CharTypeChecker : public Checker<check::PreStmt<BinaryOperator>, check::PreStmt<DeclStmt>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const;
		void checkPreStmt(const DeclStmt* DS, CheckerContext& C) const;
		void checkSignedOrUnsignedString(const QualType& QT, const Expr* E, CheckerContext& C) const;
		bool isSignedOrUnsignedChar(const QualType& QT) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void CharTypeChecker::checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
	if (B->getOpcode() == BO_Assign) {
		checkSignedOrUnsignedString(B->getLHS()->getType(), B->getRHS(), C);
	}
}

void CharTypeChecker::checkPreStmt(const DeclStmt* DS, CheckerContext& C) const {
	for (const Decl* D : DS->decls()) {
		if (const VarDecl* VD = llvm::dyn_cast_or_null<VarDecl>(D)) {
			checkSignedOrUnsignedString(VD->getType(), VD->getInit(), C);
		}
	}
}

void CharTypeChecker::checkSignedOrUnsignedString(const QualType& QT, const Expr* E, CheckerContext& C) const {
	if (!E)
		return;

	if (!isa<StringLiteral>(E->IgnoreParenCasts()))
		return;

	if (auto AT = dyn_cast<ArrayType>(QT)) {
		auto ET = AT->getElementType();
		if (!isSignedOrUnsignedChar(ET)) {
			return;
		}
	}
	else if (auto PT = dyn_cast<PointerType>(QT)) {
		auto ET = PT->getPointeeType();
		if (!isSignedOrUnsignedChar(ET)) {
			return;
		}
	}
	else {
		return;
	}

	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::CharTypeChecker, lang);
	reportBug(FD, Msg, E->getBeginLoc(), C.getBugReporter());
}

bool CharTypeChecker::isSignedOrUnsignedChar(const QualType& QT) const {
	auto BT = dyn_cast<BuiltinType>(QT);
	if (!BT)
		return false;

	return BT->getKind() == BuiltinType::Kind::SChar || BT->getKind() == BuiltinType::Kind::UChar;
}

void CharTypeChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "CharTypeChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CharTypeChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCharTypeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CharTypeChecker>();
}

bool ento::shouldRegisterCharTypeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CharTypeChecker>("anzu.CharTypeChecker", "", "");
}

#endif
