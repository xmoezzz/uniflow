#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class SwitchDeclInFirstCasePreChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const;
	};

	class Visitor : public RecursiveASTVisitor<Visitor> {
		BugReporter& BR;
		AnalysisManager& Mgr;
		BuiltinBug& BT;
		const FunctionDecl* FD;

	public:
		Visitor(const FunctionDecl* FD, BugReporter& BR, AnalysisManager& Mgr, BuiltinBug& BT)
			: FD(FD), BR(BR), Mgr(Mgr), BT(BT) {}

		bool VisitSwitchStmt(SwitchStmt* SS) {
			if (auto Body = SS->getBody()) {
				if (auto CS = dyn_cast<CompoundStmt>(Body)) {
					DeclStmt* FirstDS = nullptr;
					bool IsCase = false;
					auto ls = anzulocalization::LocaleSetting::getInstance();
					uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
					std::string Msg = ls->parseMsgs(anzulocalization::SwitchDeclInFirstCasePreChecker, lang);
					for (auto Child : CS->children()) {
						if (auto DS = dyn_cast<DeclStmt>(Child)) {
							FirstDS = DS;
						}

						if (isa<CaseStmt>(Child)) {
							IsCase = true;
						}

						if (!FirstDS)
							break;
					}

					if (FirstDS && IsCase) {
						reportBug(FD, Msg, FirstDS->getBeginLoc(), BR);
					}
				}
			}
			return true;
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				BT, Msg, createRuleExtData(1, "SwitchDeclInFirstCasePreChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

	void SwitchDeclInFirstCasePreChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
		BugReporter& BR) const {
		if (!D)
			return;

		if (!BT)
			BT.reset(new BuiltinBug(this, "SwitchDeclInFirstCasePreChecker"));

		Visitor V(dyn_cast<FunctionDecl>(D), BR, Mgr, *BT);
		V.TraverseDecl(const_cast<Decl*>(D));
	}
}


/// Checker registration
#if RELEASE_BUNDLE
void ento::registerSwitchDeclInFirstCasePreChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<SwitchDeclInFirstCasePreChecker>();
}

bool ento::shouldRegisterSwitchDeclInFirstCasePreChecker(const CheckerManager& mgr) {
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
	registry.addChecker<SwitchDeclInFirstCasePreChecker>("anzu.SwitchDeclInFirstCasePreChecker", "", "");
}

#endif