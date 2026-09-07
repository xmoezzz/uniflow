#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class GotoChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
	};

	class GotoVisitor : public RecursiveASTVisitor<GotoVisitor> {
		BugReporter& BR;
		BuiltinBug& BT;
		const FunctionDecl* FD;

	public:
		GotoVisitor(const FunctionDecl* FD, BugReporter& BR, BuiltinBug& BT)
			: FD(FD), BR(BR), BT(BT) {}

		bool VisitGotoStmt(const GotoStmt* GS) {
			if (GS->getBeginLoc().isMacroID())
				return true;

			const LabelDecl* LD = GS->getLabel();
			const LabelStmt* LS = LD->getStmt();
			if (LS) {
				if (LS->getBeginLoc() < GS->getGotoLoc()) {
					auto ls = anzulocalization::LocaleSetting::getInstance();
					uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
					std::string Msg = ls->parseMsgs(anzulocalization::GotoChecker, lang);
					reportBug(GS->getBeginLoc(), Msg);
				}
			}
			return true;
		}

		void reportBug(SourceLocation Loc, llvm::StringRef Message) {
			if (Loc.isMacroID())
				return;
			
			PathDiagnosticLocation PathLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				BT, Message, createRuleExtData(1, "GotoChecker"), PathLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

	void GotoChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
		BugReporter& BR) const {
		if (!D)
			return;

		if (!BT)
			BT.reset(new BuiltinBug(this, "GotoChecker"));

		GotoVisitor V(dyn_cast<FunctionDecl>(D), BR, *BT);
		V.TraverseDecl(const_cast<Decl*>(D));
	}

}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerGotoChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<GotoChecker>();
}

bool ento::shouldRegisterGotoChecker(const CheckerManager& mgr) {
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
	registry.addChecker<GotoChecker>("anzu.GotoChecker", "goto from outside a compound statement to inside, or shared goto from lower-level to higher-level.", "");
}

#endif