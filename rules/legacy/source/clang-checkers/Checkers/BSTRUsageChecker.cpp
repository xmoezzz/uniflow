#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class BSTRUsageChecker : public Checker<check::PreStmt<CXXReinterpretCastExpr>,
		check::PreStmt<BinaryOperator>,
		check::PreStmt<CStyleCastExpr>,
		check::PreCall> {
		mutable std::unique_ptr<BugType> BT;

	public:
		BSTRUsageChecker() {}

		void checkPreStmt(const CXXReinterpretCastExpr* CE, CheckerContext& C) const {
			checkCast(CE, C);
		}

		void checkPreStmt(const CStyleCastExpr* CE, CheckerContext& C) const {
			checkCast(CE, C);
		}

		void checkPreStmt(const BinaryOperator* BO, CheckerContext& C) const {
			if (BO->getOpcode() == BO_Add && BO->getType()->isPointerType() &&
				BO->getType().getAsString() == "BSTR") {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::BSTRUsageChecker, lang, 0); 
				reportBug(Msg, BO, C);
			}
		}

		void checkPreCall(const CallEvent& Call, CheckerContext& C) const {
			const IdentifierInfo* II = Call.getCalleeIdentifier();
			if (!II) return;

			StringRef FName = II->getName();
			if (FName == "SysAllocString" && Call.getNumArgs() >= 1) {
				checkSysAllocString(Call, C);
			}
			else if (FName == "SysFreeString" || FName == "SysStringLen" || FName == "SysReAllocString") {
				if (Call.getNumArgs() >= 1) {
					const Expr* arg = Call.getArgExpr(0);
					if (arg && arg->getType().getAsString() != "BSTR") {
						auto ls = anzulocalization::LocaleSetting::getInstance();
						uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
						std::string Msg = ls->parseMsgs(anzulocalization::BSTRUsageChecker, lang, 1); 
						reportBug(Msg, arg, C);
					}
				}
			}
		}

	private:
		void checkCast(const CastExpr* CE, CheckerContext& C) const {
			QualType SrcType = CE->getSubExpr()->getType();
			QualType DestType = CE->getType();
			if (SrcType->isPointerType() && SrcType->getPointeeType()->isWideCharType() &&
				DestType->isPointerType() && DestType.getAsString() == "BSTR") {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::BSTRUsageChecker, lang, 2); 
				reportBug(Msg, CE, C);
			}
		}

		void checkSysAllocString(const CallEvent& Call, CheckerContext& C) const {
			const Expr* arg = Call.getArgExpr(0);
			if (!arg)
				return;
			QualType argType = arg->getType();
			if (argType->isPointerType() && argType.getAsString() == "BSTR") {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::BSTRUsageChecker, lang, 3); 
				reportBug(Msg, arg, C);
			}
		}

		void reportBug(std::string Msg, const Stmt* S, CheckerContext& C) const {
			ExplodedNode* N = C.generateNonFatalErrorNode();
			if (!N) return;

			if (!BT) {
				BT = std::make_unique<BuiltinBug>(this, "BSTRUsageChecker");
			}

			auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "BSTRUsageChecker"), Msg, N);
			R->addRange(S->getSourceRange());
			C.emitReport(std::move(R));
		}
	};
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBSTRUsageChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BSTRUsageChecker>();
}

bool ento::shouldRegisterBSTRUsageChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BSTRUsageChecker>("anzu.BSTRUsageChecker", "Improper use of BSTR", "");
}

#endif