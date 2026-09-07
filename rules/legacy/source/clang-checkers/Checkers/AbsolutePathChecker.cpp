#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class AbsolutePathChecker : public Checker<check::PreStmt<CallExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
			const FunctionDecl* FD = CE->getDirectCallee();
			if (!FD)
				return;

			// 检查CreateProcess和LoadLibrary函数调用
			if (FD->getIdentifier())
			{
				if (FD->getName().equals("CreateProcessA") ||
					FD->getName().equals("CreateProcessW") ||
					FD->getName().equals("CreateProcess") ||
					FD->getName().equals("LoadLibrary") ||
					FD->getName().equals("LoadLibraryA") ||
					FD->getName().equals("LoadLibraryW"))
				{
					const Expr* Arg = CE->getArg(0);
					if (Arg)
					{
						if (const StringLiteral* StrLit = llvm::dyn_cast_or_null<StringLiteral>(Arg->IgnoreImpCasts())) {
							auto StrPath = toString(StrLit);
							if (!llvm::sys::path::is_absolute(StrPath)) {
								if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
									if (!BT)
										BT.reset(new BuiltinBug(this, "AbsolutePathChecker"));
									auto ls = anzulocalization::LocaleSetting::getInstance();
									uint64_t lang = (C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
									std::string msg = ls->parseMsgs(anzulocalization::AbsolutePathChecker, lang);
									auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "AbsolutePathChecker"), msg, N);
									C.emitReport(std::move(R));
								}
							}
						}
					}
				}
			}
		}
	};
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAbsolutePathChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<AbsolutePathChecker>();
}

bool ento::shouldRegisterAbsolutePathChecker(const CheckerManager& mgr) {
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
	registry.addChecker<AbsolutePathChecker>("anzu.AbsolutePathChecker", "Checks for usage of absolute paths in loading external libraries", "");
}

#endif