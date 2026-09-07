#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

// 01000010140002

namespace {

	class LabelNameChecker : public Checker<check::ASTCodeBody> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void LabelNameChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
	const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D);
	if (!FD || !FD->hasBody())
		return;

	std::set<std::string> UnLabelNames;
	for (const Decl* decl : FD->decls()) {
		if (auto ND = llvm::dyn_cast_or_null<NamedDecl>(decl)) {
			if (const LabelDecl* labelDecl = llvm::dyn_cast_or_null<LabelDecl>(decl); labelDecl == nullptr) {
				std::string Name = ND->getName().str();
				UnLabelNames.insert(Name);
			}
		}
	}
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::LabelNameChecker, lang);

	for (const Decl* decl : FD->decls()) {
		if (const LabelDecl* labelDecl = llvm::dyn_cast_or_null<LabelDecl>(decl)) {
			std::string name = labelDecl->getName().str();
			if (UnLabelNames.find(name) != UnLabelNames.end()) {
				reportBug(FD, Msg, labelDecl->getLocation(), BR);
			}
		}
	}
}

void LabelNameChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "LabelNameChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "LabelNameChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerLabelNameChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<LabelNameChecker>();
}

bool ento::shouldRegisterLabelNameChecker(const CheckerManager& mgr) {
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
	registry.addChecker<LabelNameChecker>("anzu.LabelNameChecker", "Check duplicated label name", "");
}

#endif