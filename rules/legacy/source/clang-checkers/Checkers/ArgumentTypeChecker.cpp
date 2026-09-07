#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class ArgumentTypeChecker : public Checker<check::PreCall> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
		bool isZero(const Expr* E) const;
		bool isValidAssign(ASTContext& AST, QualType LHSType, QualType RHSType, const Expr* RE) const;
	};
} // end anonymous namespace

void ArgumentTypeChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (C.getASTContext().HasSyntaxErrors()) {
		return;
	}

	if (!Call.getDecl()) return;
	// 获取被调用函数的声明
	const FunctionDecl* FD = dyn_cast<FunctionDecl>(Call.getDecl());
	if (!FD) return;

	unsigned NumArgs = Call.getNumArgs();

	// 检查每个实参和对应的形参
	for (unsigned i = 0; i < NumArgs && i < FD->getNumParams(); ++i) {
		auto PVD = FD->getParamDecl(i);
		if (!PVD)
			continue;
		auto Arg = Call.getArgExpr(i);
		if (!Arg)
			continue;

		QualType DefineType = PVD->getType();
		auto RealType = Arg->IgnoreParenImpCasts()->getType();
		if (isValidAssign(C.getASTContext(), DefineType, RealType, Arg->IgnoreParenImpCasts()))
			continue;

		if (isZero(Arg->IgnoreParenImpCasts()))
			continue;

		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
		}

		SmallString<100> buf;
		llvm::raw_svector_ostream os(buf);

		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::ArgumentTypeChecker, lang);
		std::string dt = DefineType.getAsString();
		std::string rt = RealType.getAsString();
		std::string Msg = std::vformat(fmt, std::make_format_args(dt, rt));

		reportBug(FD, Msg, Arg->getBeginLoc(), C.getBugReporter());
	}
}

bool ArgumentTypeChecker::isValidAssign(ASTContext& AST, QualType LHSType, QualType RHSType, const Expr* RE) const {
	if (!LHSType->isIntegralOrEnumerationType() && !LHSType->isFloatingType())
		return true;

	if (LHSType == RHSType)
		return true;

	if ((LHSType->isIntegralOrEnumerationType() ^ RHSType->isIntegralOrEnumerationType()) ||
		(LHSType->isFloatingType() ^ RHSType->isFloatingType())) {
		return false;
	}

	clang::Expr::EvalResult Result;
	if (RE->IgnoreParenImpCasts()->EvaluateAsInt(Result, AST)) {
		auto Value = Result.Val.getInt();
		llvm::APSInt MaxValue;
		if (LHSType->isSignedIntegerType()) {
			MaxValue = llvm::APSInt::getMaxValue(AST.getTypeSize(LHSType), false);
		}
		else {
			MaxValue = llvm::APSInt::getMaxValue(AST.getTypeSize(LHSType), true);
		}

		auto c = llvm::APSInt::compareValues(MaxValue, Value);
		if (c < 0)
			return false;
	}

	auto LHSSize = AST.getTypeSize(LHSType);
	auto RHSSize = AST.getTypeSize(RHSType);
	if (0 == LHSSize || 0 == RHSSize)
		return true;

	if (LHSType->isSignedIntegerType()) LHSSize -= 1;
	if (RHSType->isSignedIntegerType()) RHSSize -= 1;
	if (LHSSize < RHSSize)
		return false;

	return true;
}

bool ArgumentTypeChecker::isZero(const Expr* E) const {
	if (!E) {
		return false;
	}

	E = E->IgnoreParenCasts();
	if (auto IL = dyn_cast<IntegerLiteral>(E)) {
		return IL->getValue() == 0;
	}

	return false;
}

void ArgumentTypeChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "ArgumentTypeChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ArgumentTypeChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerArgumentTypeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ArgumentTypeChecker>();
}

bool ento::shouldRegisterArgumentTypeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ArgumentTypeChecker>("anzu.ArgumentTypeChecker", "Checks argument types in function calls", "");
}

#endif