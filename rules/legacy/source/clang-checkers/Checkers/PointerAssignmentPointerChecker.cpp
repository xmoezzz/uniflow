#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class PointerAssignmentPointerChecker : public Checker<check::Bind> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkBind(SVal L, SVal V, const Stmt* S, CheckerContext& C) const {
			if (const auto* BO = llvm::dyn_cast_or_null<BinaryOperator>(S)) {
				if (BO->isAssignmentOp()) {
					if (const auto* CastE = llvm::dyn_cast_or_null<CastExpr>(BO->getRHS()->IgnoreParenImpCasts())) {
						if (auto ECE = dyn_cast<ExplicitCastExpr>(CastE)) {
							if (ECE->getCastKind() == CK_BitCast) {
								if (!checkTypeCastValid(ECE->getType(), ECE->getSubExpr()->getType())) {
									const FunctionDecl* FD = nullptr;
									if (auto LC = C.getLocationContext()) {
										if (auto D = LC->getDecl()) {
											FD = dyn_cast<FunctionDecl>(D);
										}
									}
									auto ls = anzulocalization::LocaleSetting::getInstance();
									uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
									std::string Msg = ls->parseMsgs(anzulocalization::PointerAssignmentPointerChecker, lang);
									reportBug(FD,
										Msg,
										BO->getOperatorLoc(),
										C.getBugReporter());
								}
							}
						}
					}
				}
			}
		}

		bool checkTypeCastValid(const QualType& SrcQT, const QualType& DstQT) const {
			if (SrcQT.getCanonicalType() == DstQT.getCanonicalType())
				return true;

			auto SrcPT = dyn_cast<PointerType>(SrcQT.getCanonicalType());
			if (!SrcPT)
				return true;

			auto DstPT = dyn_cast<PointerType>(DstQT.getCanonicalType());
			if (!DstPT)
				return true;

			QualType PointeeSrcQT = SrcPT->getPointeeType().getCanonicalType();
			QualType PointeeDstQT = DstPT->getPointeeType().getCanonicalType();

			if (PointeeSrcQT->isVoidType() || PointeeSrcQT->isRecordType())
				return true;

			if (PointeeDstQT->isVoidType() || PointeeDstQT->isRecordType())
				return true;

			if (PointeeSrcQT == PointeeDstQT)
				return true;

			return false;
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "PointerAssignmentPointerChecker"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "PointerAssignmentPointerChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPointerAssignmentPointerChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PointerAssignmentPointerChecker>();
}

bool ento::shouldRegisterPointerAssignmentPointerChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PointerAssignmentPointerChecker>("anzu.PointerAssignmentPointerChecker", "", "");
}

#endif
