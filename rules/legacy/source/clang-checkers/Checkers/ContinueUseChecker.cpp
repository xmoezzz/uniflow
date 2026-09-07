#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/Analysis/CFG.h"
#include "llvm/Analysis/DominanceFrontier.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "llvm/Support/GenericDomTree.h"
#include "llvm/IR/Dominators.h"
#include "clang/Analysis/Analyses/Dominators.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class ContinueUseChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		ContinueUseChecker() {}

		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
			if (const auto* FD = dyn_cast<FunctionDecl>(D)) {
				AnalysisDeclContext* ADC = Mgr.getAnalysisDeclContext(FD);
				CFG* cfg = ADC->getCFG();
				if (!cfg) {
					return;
				}

				for (const CFGBlock* Block : *cfg) {
					if (auto TS = Block->getTerminator().getStmt()) {
						if (auto CS = dyn_cast<ContinueStmt>(TS)) {
							if (isInvalidBlockWithSimpleCheck(Block)) {
								reportBug(dyn_cast<FunctionDecl>(D), CS->getContinueLoc(), BR);
							}
						}
					}
				}
			}
		}

		bool isInvalidBlockWithSimpleCheck(const CFGBlock* Block) const {
			if (!Block) {
				return false;
			}

			if (1 != Block->succ_size()) {
				return false;
			}

			if (auto Succ = *Block->succ_begin()) {
				if (1 != Succ->pred_size()) {
					auto SuccID = Succ->getBlockID();
					for (auto Pred : Block->preds()) {
						if (!Pred) {
							return false;
						}

						bool ExistSame = false;
						for (auto PSucc : Pred->succs()) {
							if (PSucc && PSucc != Block) {
								if (PSucc->getBlockID() == SuccID) {
									ExistSame = true;
									break;
								}
								else if (PSucc->succ_size() == 1 && 
									*PSucc->succ_begin() && 
									(*PSucc->succ_begin())->getBlockID() == SuccID) {
									ExistSame = true;
									break;
								}
							}
						}

						if (!ExistSame) {
							return false;
						}
					}
				}

				return true;
			}

			return false;
		}

		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "ContinueUseChecker"));
			}

			// Report the issue
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::ContinueUseChecker, lang);        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "ContinueUseChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}

	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerContinueUseChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ContinueUseChecker>();
}

bool ento::shouldRegisterContinueUseChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ContinueUseChecker>("anzu.ContinueUseChecker", "Avoid using the continue statement.", "");
}

#endif