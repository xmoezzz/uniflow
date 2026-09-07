#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class IsUseVarDeclVisitor
		: public RecursiveASTVisitor<IsUseVarDeclVisitor> {
		bool Used = false;
		const Decl* VD;

	public:
		IsUseVarDeclVisitor(const Decl* VD) : VD(VD) {}
		const bool IsUsed() {
			return Used;
		}

	public:
		bool VisitDeclRefExpr(const DeclRefExpr* DRE) {
			if (DRE) {
				if (auto D = DRE->getDecl()) {
					if (D == VD) {
						Used = true;
						return false;
					}
				}
			}
			return true;
		}
	};

	class UnusedParameterChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void UnusedParameterChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	const FunctionDecl* FD = dyn_cast_or_null<FunctionDecl>(D);
	if (!FD || !FD->hasBody())
		return;

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::UnusedParameterChecker, lang);
	// todo: lower level scan
	auto data = getSourceCode(Mgr.getASTContext(), FD->getBeginLoc(), FD->getEndLoc());
	for (const auto P : FD->parameters()) {
		if (!P)
			continue;
		if (P->getName().empty())
			continue;
		if (data.find(P->getNameAsString()) != std::string::npos)
			continue;

		IsUseVarDeclVisitor Visitor(P);
		Visitor.TraverseDecl(const_cast<Decl*>(D));
		if (!Visitor.IsUsed()) {
			reportBug(FD, Msg, P->getLocation(), BR);
		}
	}
}

void UnusedParameterChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "UnusedParameterChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "UnusedParameterChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerUnusedParameterChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<UnusedParameterChecker>();
}

bool ento::shouldRegisterUnusedParameterChecker(const CheckerManager& mgr) {
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
	registry.addChecker<UnusedParameterChecker>("anzu.UnusedParameterChecker", "Detects unused parameters in function declarations", "");
}

#endif