#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"
#include <vector>

using namespace clang;
using namespace ento;

namespace {
	class UseSizeofCalLengthChecker : public Checker<check::PostStmt<ExplicitCastExpr>> {
		std::vector<std::pair<std::string, int>> CheckFuncs = {
			{"malloc", 0},
			{"calloc", 1},
			{"realloc", 1},
		};
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPostStmt(const ExplicitCastExpr* ECE, CheckerContext& C) const {
			if (!ECE->getType()->isPointerType())
				return;

			auto E = ECE->getSubExpr();
			if (!E)
				return;

			auto CE = dyn_cast<CallExpr>(E);
			if (!CE)
				return;

			auto FD = CE->getDirectCallee();
			if (!FD)
				return;

			auto Name = FD->getNameAsString();
			for (auto& CF : CheckFuncs) {
				if (CF.first == Name) {
					if (!checkAllocLength(CE, CF.second)) {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}

						reportBug(FD, CE->getArg(CF.second)->getBeginLoc(), C.getBugReporter());
					}
					break;
				}
			}
		}

		bool checkAllocLength(const CallExpr* CE, int Pos) const {
			if (Pos >= CE->getNumArgs())
				return true;

			auto Arg = CE->getArg(Pos);
			if (!Arg)
				return true;

			std::list<const Expr*> Queues;
			Queues.push_back(Arg);
			while (!Queues.empty()) {
				auto E = Queues.front()->IgnoreParenCasts();
				Queues.pop_front();

				if (auto BO = dyn_cast<BinaryOperator>(E)) {
					if (auto LHS = BO->getLHS()) {
						Queues.push_back(LHS);
					}
					if (auto RHS = BO->getRHS()) {
						Queues.push_back(RHS);
					}
				}
				else if (!IsConstantExpr(E)) {
					return true;
				}
			}

			return false;
		}

		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "UseSizeofCalLengthChecker"));

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::UseSizeofCalLengthChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "UseSizeofCalLengthChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}

	};
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUseSizeofCalLengthChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UseSizeofCalLengthChecker>();
}

bool ento::shouldRegisterUseSizeofCalLengthChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::C);
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
	registry.addChecker<UseSizeofCalLengthChecker>("anzu.UseSizeofCalLengthChecker", "", "");
}

#endif
