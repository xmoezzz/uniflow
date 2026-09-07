#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class PointerTypeCastChecker
		: public Checker<check::PreStmt<ExplicitCastExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const ExplicitCastExpr* CE, CheckerContext& C) const {
			QualType DestType = CE->getType();
			QualType SrcType = CE->getSubExpr()->getType();

			if (IsConstantExpr(CE->getSubExpr()))
				return;

			// 如果源类型和目标类型都是指针类型，且它们不兼容
			if (DestType->isPointerType() && SrcType->isPointerType() &&
				!C.getASTContext().hasSameType(DestType->getPointeeType().getUnqualifiedType(),
					SrcType->getPointeeType().getUnqualifiedType()) &&
				!DestType->isVoidPointerType() && !SrcType->isVoidPointerType()) {

				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}

				reportBug(FD, CE->getExprLoc(), C.getBugReporter());
			}
			// pointer & scaler
			if (DestType->isPointerType() && !DestType->isVoidPointerType() &&
				SrcType->isIntegerType()) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}

				reportBug(FD, CE->getExprLoc(), C.getBugReporter());
			}
			if (SrcType->isPointerType() && !SrcType->isVoidPointerType() &&
				DestType->isIntegerType()) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}

				reportBug(FD, CE->getExprLoc(), C.getBugReporter());
			}
		}

		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
					
			if (!BT)
				BT.reset(new BuiltinBug(this, "PointerTypeCastChecker"));

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::PointerTypeCastChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "PointerTypeCastChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPointerTypeCastChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PointerTypeCastChecker>();
}

bool ento::shouldRegisterPointerTypeCastChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PointerTypeCastChecker>("anzu1.PointerTypeCastChecker", "Detects unsafe pointer type conversions", "");
}

#endif
