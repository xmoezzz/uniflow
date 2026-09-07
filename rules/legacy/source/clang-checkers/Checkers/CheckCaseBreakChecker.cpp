#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/StmtVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/Analysis/CFG.h"
#include "../Utils.h"
#include <list>
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {
	class CheckCaseBreakChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		bool ExistBreakStmt(const CFGBlock* Block) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void CheckCaseBreakChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	if (const auto* FD = dyn_cast<FunctionDecl>(D)) {
		AnalysisDeclContext* ADC = Mgr.getAnalysisDeclContext(FD);
		CFG* cfg = ADC->getCFG();
		if (!cfg) {
			return;
		}
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::CheckCaseBreakChecker, lang);
		for (auto N : cfg->nodes()) {
			if (auto S = N->Label) {
				if (isa<CaseStmt>(S)/* || isa<DefaultStmt>(S)*/) {
					if (!ExistBreakStmt(N)) {
						reportBug(FD, Msg, S->getBeginLoc(), BR);
					}
				}
			}
		}
	}
}

bool CheckCaseBreakChecker::ExistBreakStmt(const CFGBlock* Block) const {
	if (!Block)
		return true;

	std::unordered_set<const CFGBlock*> ExistBlocks{ Block };
	std::list<const CFGBlock*> CheckBlocks{ Block };
	while (!CheckBlocks.empty()) {
		auto CurBlock = CheckBlocks.front();
		CheckBlocks.pop_front();

		if (Block != CurBlock) {
			if (auto S = CurBlock->Label) {
				if (isa<CaseStmt>(S)/* || isa<DefaultStmt>(S)*/) {
					return false;
				}
			}
		}

		if (auto TS = CurBlock->getTerminator().getStmt()) {
			if (isa<BreakStmt>(TS)) {
				continue;
			}
			// ignore child switch stmt
			if (isa<SwitchStmt>(TS)) {
				return true;
			}
		}

		bool ExistReturn = false;
		for (auto Elem : *CurBlock) {
			if (Elem.getKind() == CFGElement::Statement) {
				if (auto S = Elem.castAs<CFGStmt>().getStmt()) {
					if (isa<ReturnStmt>(S)) {
						ExistReturn = true;
					}
				}
			}
		}
		if (ExistReturn)
			continue;

		bool ExistChild = false;
		for (auto AdjaBlock : CurBlock->succs()) {
			CFGBlock* ChildBlock = AdjaBlock;
			if (!ChildBlock || ExistBlocks.find(ChildBlock) != ExistBlocks.end())
				continue;
			ExistBlocks.insert(ChildBlock);
			CheckBlocks.push_back(ChildBlock);
			ExistChild = true;
		}

		if (!ExistChild)
			return false;
	}

	return true;
}

void CheckCaseBreakChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "CheckCaseBreakChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CheckCaseBreakChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCheckCaseBreakChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CheckCaseBreakChecker>();
}

bool ento::shouldRegisterCheckCaseBreakChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CheckCaseBreakChecker>("anzu1.CheckCaseBreakChecker", "", "");
}

#endif