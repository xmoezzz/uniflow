#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Frontend/CheckerRegistry.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Stmt.h"
#include "llvm/Support/raw_ostream.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class ShiftOverflowChecker : public Checker< check::PreStmt<BinaryOperator> > {
		mutable std::unique_ptr<BuiltinBug> BT;
	public:
		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
			if (B->getOpcode() != BO_Shl && B->getOpcode() != BO_Shr) {
				return;
			}

			// 获取操作数类型的位数
			QualType T = B->getLHS()->getType();
			uint64_t TypeSize = C.getASTContext().getTypeSize(T);

			// 获取右侧的符号值
			const Expr* RHS = B->getRHS();
			SVal RHSVal = C.getSVal(RHS);
			Optional<nonloc::ConcreteInt> RHSC = RHSVal.getAs<nonloc::ConcreteInt>();
			if (!RHSC)
				return;

			// 检查移位数量是否大于类型的位数
			if (RHSC->getValue().getLimitedValue() >= TypeSize) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::ShiftOverflowChecker, lang);

				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				reportBug(FD, Msg, B->getOperatorLoc(), C.getBugReporter());
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "ShiftOverflowChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "ShiftOverflowChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerShiftOverflowChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ShiftOverflowChecker>();
}

bool ento::shouldRegisterShiftOverflowChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ShiftOverflowChecker>("anzu.ShiftOverflowChecker", "Checks for shifts beyond the variable size", "");
}

#endif