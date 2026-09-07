#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/StmtCXX.h"
#include "../Utils.h"
#include <map>

using namespace clang;
using namespace ento;

namespace {
	struct OVERLOAD_OO
	{
		const FunctionDecl* FD = nullptr;
		bool HasNew = false;
		bool HasDelete = false;
		bool HasArrayNew = false;
		bool HasArrayDelete = false;
	};

	class AllocationDeallocationChecker : public Checker<check::ASTCodeBody, check::EndOfTranslationUnit> {
		mutable std::unique_ptr<BugType> BT;
		mutable std::map<std::string, OVERLOAD_OO> FunctionOverloaded;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const {

			if (const CXXRecordDecl* RD = llvm::dyn_cast_or_null<CXXRecordDecl>(D)) {
				checkCXXRecordDecl(RD, BR);
			}
			else if (const FunctionDecl* FD = llvm::dyn_cast_or_null<FunctionDecl>(D)) {
				checkFunctionDecl(FD, BR);
			}
		}

		void checkEndOfTranslationUnit(const TranslationUnitDecl* TU,
			AnalysisManager& mgr,
			BugReporter& BR) const {
			for (auto& FO : FunctionOverloaded) {
				if (FO.second.HasNew != FO.second.HasDelete) {
					reportBug(FO.second.FD, "operator new and operator delete", FO.second.FD->getBeginLoc(), BR);
				}
				if (FO.second.HasArrayNew != FO.second.HasArrayDelete) {
					reportBug(FO.second.FD, "operator new[] and operator delete[]", FO.second.FD->getBeginLoc(), BR);
				}
			}
		}

		void checkCXXRecordDecl(const CXXRecordDecl* RD, BugReporter& BR) const {
			if (!RD || !RD->hasDefinition())
				return;

			bool hasNew = false, hasDelete = false;
			bool hasArrayNew = false, hasArrayDelete = false;
			const FunctionDecl* NewDelFD = nullptr;
			const FunctionDecl* NewDelArrayFD = nullptr;

			for (const CXXMethodDecl* MD : RD->methods()) {
				if (MD->isOverloadedOperator()) {
					OverloadedOperatorKind OOK = MD->getOverloadedOperator();

					switch (OOK) {
					case OO_New:
						hasNew = true;
						NewDelFD = MD;
						break;
					case OO_Delete:
						hasDelete = true;
						NewDelFD = MD;
						break;
					case OO_Array_New:
						hasArrayNew = true;
						NewDelArrayFD = MD;
						break;
					case OO_Array_Delete:
						hasArrayDelete = true;
						NewDelArrayFD = MD;
						break;
					default:
						break;
					}
				}
			}

			if (hasNew != hasDelete) {
				reportBug(NewDelFD, "operator new and operator delete", NewDelFD->getBeginLoc(), BR);
			}
			if (hasArrayNew != hasArrayDelete) {
				reportBug(NewDelArrayFD, "operator new[] and operator delete[]", NewDelArrayFD->getBeginLoc(), BR);
			}
		}

		void checkFunctionDecl(const FunctionDecl* FD, BugReporter& BR) const {
			if (!FD || !FD->hasBody() || !FD->isOverloadedOperator())
				return;

			std::string DomainName;
			if (auto DC = FD->getParent()) {
				if (auto ND = dyn_cast<NamespaceDecl>(DC)) {
					DomainName = ND->getNameAsString();
				}
				else if (auto TUD = dyn_cast<TranslationUnitDecl>(DC)) {
					DomainName = "";
				}
				else
				{
					return;
				}
			}
			else
			{
				return;
			}

			auto it = FunctionOverloaded.find(DomainName);
			if (it == FunctionOverloaded.end()) {
				FunctionOverloaded.insert(std::make_pair(DomainName, OVERLOAD_OO()));
				it = FunctionOverloaded.find(DomainName);
			}

			OverloadedOperatorKind OOK = FD->getOverloadedOperator();

			switch (OOK) {
			case OO_New:
				it->second.HasNew = true;
				break;
			case OO_Delete:
				it->second.HasDelete = true;
				break;
			case OO_Array_New:
				it->second.HasArrayNew = true;
				break;
			case OO_Array_Delete:
				it->second.HasArrayDelete = true;
				break;
			default:
				break;
			}
			it->second.FD = FD;
		}

	private:
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			auto ls = anzulocalization::LocaleSetting::getInstance();
            uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
            std::string msg = std::vformat(ls->parseMsgs(anzulocalization::AllocationDeallocationChecker, lang), std::make_format_args(Msg));

			if (!BT)
				BT.reset(new BuiltinBug(this, "AllocationDeallocationChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, msg, createRuleExtData(1, "AllocationDeallocationChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};

} // end of anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerAllocationDeallocationChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<AllocationDeallocationChecker>();
}

bool ento::shouldRegisterAllocationDeallocationChecker(const CheckerManager& mgr) {
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
	registry.addChecker<AllocationDeallocationChecker>("anzu.AllocationDeallocationChecker", "", "");
}

#endif