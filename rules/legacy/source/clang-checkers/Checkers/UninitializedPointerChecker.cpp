#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class UninitializedPointerChecker
		: public Checker<check::Bind> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkBind(const SVal& location, const SVal& val, const Stmt* S,
			CheckerContext& C) const {
			if (C.getASTContext().HasSyntaxErrors()) {
				return;
			}

			auto DS = dyn_cast<DeclStmt>(S);
			if (!DS)
				return;

			for (auto D : DS->decls()) {
				if (!D)
					continue;

				auto VD = dyn_cast<VarDecl>(D);
				if (!VD)
					continue;

				if (isa<ParmVarDecl>(VD))
					continue;

				if (VD->getType()->isReferenceType()) {
					checkReference(VD, C);
				}

				if (VD->getType()->isPointerType()) {
					checkPointer(VD, C);
				}
			}
		}

		void checkReference(const VarDecl* VD, CheckerContext& C) const {
			auto Init = VD->getInit();
			if (!Init)
				return;

			Init = Init->IgnoreParenCasts();
			if (!isa<DeclRefExpr>(Init))
				return;

			if (!C.getSVal(Init).isUndef())
				return;

			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, Init->getBeginLoc(), C.getBugReporter());
		}

		void checkPointer(const VarDecl* VD, CheckerContext& C) const {
			auto Init = VD->getInit();
			if (!Init)
				return;

			auto UO = dyn_cast<UnaryOperator>(Init->IgnoreParenCasts());
			if (!UO)
				return;

			if (UO->getOpcode() != UnaryOperator::Opcode::UO_AddrOf)
				return;

			auto DRE = UO->getSubExpr();
			if (!isa<DeclRefExpr>(DRE))
				return;

			if (!C.getSVal(DRE).isUndef())
				return;

			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}
			reportBug(FD, DRE->getBeginLoc(), C.getBugReporter());
		}

		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "UninitializedPointerChecker"));

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::UninitializedPointerChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "UninitializedPointerChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUninitializedPointerChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UninitializedPointerChecker>();
}

bool ento::shouldRegisterUninitializedPointerChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UninitializedPointerChecker>("anzu.UninitializedPointerChecker", "Detects uninitialized pointer or reference arguments", "");
}

#endif