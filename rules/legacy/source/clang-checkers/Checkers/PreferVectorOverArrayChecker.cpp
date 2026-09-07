#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class PreferVectorOverArrayChecker : public Checker<check::PostStmt<DeclStmt>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPostStmt(const DeclStmt* DS, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void PreferVectorOverArrayChecker::checkPostStmt(const DeclStmt* DS, CheckerContext& C) const {
		for (const auto* D : DS->decls()) {
			if (const auto* VD = llvm::dyn_cast_or_null<VarDecl>(D)) {
				if (auto RD = VD->getType()->getAsCXXRecordDecl()) {
					auto Name = RD->getQualifiedNameAsString();
					if (Name.find("std::array") == 0) {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}

						reportBug(FD, VD->getBeginLoc(), C.getBugReporter());
					}
				}
			}
		}
	}

	void PreferVectorOverArrayChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
				
		if (!BT)
			BT.reset(new BuiltinBug(this, "PreferVectorOverArrayChecker"));

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::PreferVectorOverArrayChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "PreferVectorOverArrayChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerPreferVectorOverArrayChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<PreferVectorOverArrayChecker>();
}

bool ento::shouldRegisterPreferVectorOverArrayChecker(const CheckerManager& mgr) {
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
	registry.addChecker<PreferVectorOverArrayChecker>("anzu.PreferVectorOverArrayChecker", "", "");
}

#endif