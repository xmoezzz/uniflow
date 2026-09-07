#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

#include <unordered_set>
#include <unordered_map>

using namespace clang;
using namespace clang::ento;

namespace {
	class EnumNameChecker : public Checker<check::ASTDecl<VarDecl>, check::ASTDecl<EnumDecl>> {
		mutable std::unique_ptr<BugType> BT;
		mutable std::unordered_map<const DeclContext*, std::unordered_set<std::string>> EnumNames;
		mutable std::unordered_map<const DeclContext*, std::unordered_set<std::string>> VarNames;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void checkASTDecl(const EnumDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;

	private:
		void checkEnumName(const NamedDecl* ND, BugReporter& BR) const;
		void checkVarName(const NamedDecl* ND, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void EnumNameChecker::checkASTDecl(const EnumDecl* ED, AnalysisManager& Mgr, BugReporter& BR) const {
	for (const auto* ECD : ED->enumerators()) {
		checkEnumName(ECD, BR);
		if (!ECD->getName().str().empty())
			EnumNames[ED->getDeclContext()].insert(ECD->getName().str());
	}
}

void EnumNameChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr, BugReporter& BR) const {
	checkVarName(VD, BR);
	VarNames[VD->getDeclContext()].insert(VD->getName().str());
}

void EnumNameChecker::checkEnumName(const NamedDecl* ND, BugReporter& BR) const {
	auto FD = findFunctionDecl(ND);
	std::string Name = ND->getName().str();
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::EnumNameChecker, lang);
	for (auto DC = ND->getDeclContext(); DC; DC = DC->getParent()) {
		if (auto it = VarNames.find(DC); it != VarNames.end()) {
			if (it->second.find(Name) != it->second.end()) {
				std::string Msg = std::vformat(fmt, std::make_format_args(Name));
				reportBug(FD, Msg, ND->getBeginLoc(), BR);
			}
		}
	}
}

void EnumNameChecker::checkVarName(const NamedDecl* ND, BugReporter& BR) const {
	auto FD = findFunctionDecl(ND);
	std::string Name = ND->getName().str();
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::EnumNameChecker, lang);
	for (auto DC = ND->getDeclContext(); DC; DC = DC->getParent()) {
		if (auto it = EnumNames.find(DC); it != EnumNames.end()) {
			if (it->second.find(Name) != it->second.end()) {
				std::string Msg = std::vformat(fmt, std::make_format_args(Name));
				reportBug(FD, Msg, ND->getBeginLoc(), BR);
			}
		}
	}
}

void EnumNameChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "EnumNameChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "EnumNameChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerEnumNameChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<EnumNameChecker>();
}

bool ento::shouldRegisterEnumNameChecker(const CheckerManager& mgr) {
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
	registry.addChecker<EnumNameChecker>("anzu.EnumNameChecker", "Prohibit variable names that match enumerator names", "");
}

#endif