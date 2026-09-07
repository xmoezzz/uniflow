#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Decl.h"
#include <unordered_set>
#include <unordered_map>
#include <string>
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {

	class FunctionNameAsIdentifierChecker : public Checker<check::ASTDecl<VarDecl>, check::ASTDecl<FieldDecl>, check::ASTDecl<FunctionDecl>, check::EndOfTranslationUnit> {
		mutable std::unique_ptr<BuiltinBug> BT;
		mutable std::unordered_set<std::string> functionNames;
		mutable std::unordered_map<std::string, std::unordered_set<const DeclaratorDecl*>> variableNames;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void checkASTDecl(const FieldDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
			AnalysisManager& mgr,
			BugReporter& BR) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void FunctionNameAsIdentifierChecker::checkASTDecl(const FunctionDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
		if (!D)
			return;

		std::string&& Name = D->getQualifiedNameAsString();
		functionNames.insert(Name);
	}

	void FunctionNameAsIdentifierChecker::checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
		if (!D)
			return;

		std::string&& Name = D->getQualifiedNameAsString();
		variableNames[Name].insert(D);
	}

	void FunctionNameAsIdentifierChecker::checkASTDecl(const FieldDecl* D, AnalysisManager& Mgr, BugReporter& BR) const {
		if (!D)
			return;

		std::string&& Name = D->getQualifiedNameAsString();
		variableNames[Name].insert(D);
	}

	void FunctionNameAsIdentifierChecker::checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
		AnalysisManager& mgr,
		BugReporter& BR) const {
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string fmt = ls->parseMsgs(anzulocalization::FunctionNameAsIdentifierChecker, lang);
		for (auto Var : variableNames) {
			auto Name = Var.first;
			for (auto D : Var.second) {
				if (functionNames.find(Name) != functionNames.end()) {
					std::string Msg = std::vformat(fmt, std::make_format_args(Name));
					reportBug(findFunctionDecl(D), Msg, D->getBeginLoc(), BR);
				}
			}
		}
	}

	void FunctionNameAsIdentifierChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "FunctionNameAsIdentifierChecker"));
		}

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "FunctionNameAsIdentifierChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
}


/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFunctionNameAsIdentifierChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FunctionNameAsIdentifierChecker>();
}

bool ento::shouldRegisterFunctionNameAsIdentifierChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FunctionNameAsIdentifierChecker>("anzu1.FunctionNameAsIdentifierChecker", "", "");
}

#endif