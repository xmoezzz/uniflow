#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class OnlyNonPointerTypeTypedefChecker : public Checker<check::ASTDecl<TypedefDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const TypedefDecl* TD, AnalysisManager& Mgr,
			BugReporter& BR) const {
			// 检查typedef是否为指针类型
			auto QT = TD->getUnderlyingType();
			if (QT->isPointerType() && !QT->isFunctionPointerType()) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::OnlyNonPointerTypeTypedefChecker, lang);
				reportBug(findFunctionDecl(TD), Msg, TD->getBeginLoc(), BR);
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "OnlyNonPointerTypeTypedefChecker"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "OnlyNonPointerTypeTypedefChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerOnlyNonPointerTypeTypedefChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<OnlyNonPointerTypeTypedefChecker>();
}

bool ento::shouldRegisterOnlyNonPointerTypeTypedefChecker(const CheckerManager& mgr) {
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
	registry.addChecker<OnlyNonPointerTypeTypedefChecker>("anzu1.OnlyNonPointerTypeTypedefChecker", "Only use typedef on non-pointer types", "");
}

#endif