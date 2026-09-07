#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "../Utils.h"
#include <unordered_set>

using namespace clang;
using namespace clang::ento;

namespace {
	class OverloadAllVirtualFuncChecker : public Checker<check::ASTDecl<CXXRecordDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const CXXRecordDecl* RD, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void OverloadAllVirtualFuncChecker::checkASTDecl(const CXXRecordDecl* RD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!RD->isClass())
		return;

	if (!RD->hasDefinition())
		return;

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::OverloadAllVirtualFuncChecker, lang);
	for (const auto& Base : RD->bases()) {
		CXXRecordDecl* BaseDecl = Base.getType()->getAsCXXRecordDecl();
		if (!BaseDecl) continue;

		std::unordered_set<const IdentifierInfo *> AlreadyVisits;
		for (const auto* M : RD->methods()) {
			if (M->isVirtual()) {
				if (AlreadyVisits.find(M->getDeclName().getAsIdentifierInfo()) != AlreadyVisits.end())
					continue;

				AlreadyVisits.insert(M->getDeclName().getAsIdentifierInfo());

				std::unordered_set<std::string> ImplNames;
				auto ImplResult = RD->lookup(M->getDeclName());
				for (auto* D : ImplResult) {
					if (auto* MD = llvm::dyn_cast_or_null<CXXMethodDecl>(D)) {
						if (MD->isVirtual()) {
							auto Name = getFunctionNameForDeclEx(MD);
							if (!Name.empty()) {
								ImplNames.insert(Name);
							}
						}
					}
				}

				if (ImplNames.empty())
					continue;

				auto lookupResult = BaseDecl->lookup(M->getDeclName());
				for (auto BaseMD : lookupResult) {
					auto Name = getFunctionNameForDeclEx(BaseMD);
					if (ImplNames.find(Name) == ImplNames.end()) {
						std::string name = BaseMD->getQualifiedNameAsString();
						std::string Msg = std::vformat(fmt, std::make_format_args(name));
						reportBug(RD, Msg, BaseMD->getBeginLoc(), BR);
					}
				}
			}
		}
	}
}

void OverloadAllVirtualFuncChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "OverloadAllVirtualFuncChecker"));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "OverloadAllVirtualFuncChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerOverloadAllVirtualFuncChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<OverloadAllVirtualFuncChecker>();
}

bool ento::shouldRegisterOverloadAllVirtualFuncChecker(const CheckerManager& mgr) {
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
	registry.addChecker<OverloadAllVirtualFuncChecker>("anzu.OverloadAllVirtualFuncChecker", "", "");
}

#endif
