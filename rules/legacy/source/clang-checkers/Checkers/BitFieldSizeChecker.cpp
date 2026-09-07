#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

class BitFieldSizeChecker : public Checker<check::ASTDecl<FieldDecl>> {
	mutable std::unique_ptr<BuiltinBug> BT;

public:
	void checkASTDecl(const FieldDecl* D, AnalysisManager& Mgr,
		BugReporter& BR) const {
		ASTContext& Ctx = BR.getContext();
		if (D->isBitField() && D->getType()->isSignedIntegerType()) { // 确保类型为有符号整数
			Expr* BitWidthExpr = D->getBitWidth();
			llvm::APSInt BitWidth = BitWidthExpr->EvaluateKnownConstInt(Ctx);
			if (BitWidth < 2) {
				SmallString<100> Buf;
				SmallString<4> bw;
				llvm::raw_svector_ostream OS(Buf);

				BitWidth.toString(bw);
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
				auto fmt = ls->parseMsgs(anzulocalization::BitFieldSizeChecker, lang);
				std::string dname = D->getNameAsString();
				std::string bwstr = bw.str().str();
				std::string Msg = std::vformat(fmt, std::make_format_args(dname, bwstr));

				const Decl* FD = nullptr;
				if (auto AC = Mgr.getAnalysisDeclContext(D)) {
					FD = AC->getDecl();
				}
				reportBug(FD, Msg, D->getBeginLoc(), BR);
			}
		}
	}

	void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "BitFieldSizeChecker"));

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "BitFieldSizeChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
};

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBitFieldSizeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BitFieldSizeChecker>();
}

bool ento::shouldRegisterBitFieldSizeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BitFieldSizeChecker>("anzu.BitFieldSizeChecker", "Prohibit assigning negative values to unsigned type variables", "");
}

#endif