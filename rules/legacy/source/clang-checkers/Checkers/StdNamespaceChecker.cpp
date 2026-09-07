#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {

	class StdNamespaceChecker : public Checker<check::ASTDecl<NamespaceDecl>> {
	public:
		mutable std::unique_ptr<BuiltinBug> BT;

		void checkASTDecl(const NamespaceDecl* ND, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	class StdNamespaceCheckerCallback : public MatchFinder::MatchCallback {
	private:
		const FunctionDecl* FD;
		const StdNamespaceChecker& Checker;
		BugReporter& BR;

	public:
		StdNamespaceCheckerCallback(const FunctionDecl* FD, const StdNamespaceChecker& checker, BugReporter& BR) : FD(FD), Checker(checker), BR(BR) {}

		virtual void run(const MatchFinder::MatchResult& Result) override {
			if (const NamedDecl* ND = Result.Nodes.getNodeAs<NamedDecl>("declInStdOrPosix")) {
				if (const NamespaceDecl* NSD = Result.Nodes.getNodeAs<NamespaceDecl>("namespace")) {
					llvm::StringRef NamespaceName = NSD->getName();

					if (NamespaceName == "std" || NamespaceName == "posix") {
						Checker.reportBug(FD, ND->getBeginLoc(), BR);
					}
				}
			}
		}
	};

	auto NamespaceMatcher = namespaceDecl(
		hasAnyName("std", "posix"),
		unless(hasDescendant(classTemplateSpecializationDecl())),  // Exception for explicit template specialization
		hasDescendant(namedDecl().bind("declInStdOrPosix"))
	).bind("namespace");

	void StdNamespaceChecker::checkASTDecl(const NamespaceDecl* ND, AnalysisManager& Mgr, BugReporter& BR) const {
		if (Mgr.getSourceManager().isInSystemHeader(ND->getBeginLoc()))
			return;

		auto FilePath = Mgr.getSourceManager().getFilename(ND->getBeginLoc());
		auto FileName = llvm::sys::path::filename(FilePath);
		auto ExtName = llvm::sys::path::extension(FileName);
		if (ExtName != ".cpp" && ExtName != ".h")
			return;

		MatchFinder Finder;
		StdNamespaceCheckerCallback Callback(nullptr, *this, BR);

		Finder.addMatcher(NamespaceMatcher, &Callback);
		Finder.match(*ND, Mgr.getASTContext());
	}

	void StdNamespaceChecker::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "StdNamespaceChecker"));

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::StdNamespaceChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "StdNamespaceChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerStdNamespaceChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<StdNamespaceChecker>();
}

bool ento::shouldRegisterStdNamespaceChecker(const CheckerManager& mgr) {
	return IsEnableChecker(mgr.getAnalyzerOptions(), CheckerLanguage::CPP);
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
	registry.addChecker<StdNamespaceChecker>("anzu.StdNamespaceChecker", "", "");
}

#endif
