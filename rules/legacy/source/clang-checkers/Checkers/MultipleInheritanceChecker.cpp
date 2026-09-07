#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/DeclCXX.h"
#include <set>
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	class MultipleInheritanceChecker : public Checker<check::ASTDecl<CXXRecordDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const CXXRecordDecl* RD, AnalysisManager& AM, BugReporter& BR) const {
			if (!RD || !RD->hasDefinition() || !RD->isClass())
				return;

			if (RD->getNumBases() < 2) {
				return;
			}

			std::set<std::string> MemberNames;

			for (const auto& B : RD->bases()) {
				const auto* BaseClass = B.getType()->getAsCXXRecordDecl();
				if (!BaseClass) continue;

				for (const auto& D : BaseClass->decls()) {
					std::string Name;
					if (auto FD = dyn_cast<FieldDecl>(D)) {
						Name = FD->getNameAsString();
					}

					if (auto MD = dyn_cast<CXXMethodDecl>(D)) {
						Name = getFunctionNameForDeclEx(MD);
					}

					if (Name.empty())
						continue;

					if (MemberNames.find(Name) != MemberNames.end()) {
						auto ls = anzulocalization::LocaleSetting::getInstance();
						uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
						std::string fmt = ls->parseMsgs(anzulocalization::MultipleInheritanceChecker, lang);
						std::string rd = RD->getNameAsString();
						std::string bc = BaseClass->getNameAsString();
						std::string Msg = std::vformat(fmt, std::make_format_args(rd, bc, Name));

						reportBug(RD, Msg, RD->getBeginLoc(), BR);
					}
					else {
						MemberNames.insert(Name);
					}
				}
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "MultipleInheritanceChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "MultipleInheritanceChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMultipleInheritanceChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MultipleInheritanceChecker>();
}

bool ento::shouldRegisterMultipleInheritanceChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MultipleInheritanceChecker>("anzu.MultipleInheritanceChecker", "", "");
}

#endif
