#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/Expr.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include <unordered_map>
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
	class NotMatchTypePointerAccessChecker : public Checker<check::Location> {
		mutable std::unique_ptr<BuiltinBug> BT;
		mutable std::unordered_map<const LocationContext*, std::vector<const MemRegion*>> ParamInfos;

	public:
		void checkLocation(const SVal& location, bool isLoad, const Stmt* S, CheckerContext& C) const;
		bool getOriginSize(const MemRegion* MR, uint64_t& size, CheckerContext& C) const;
		bool getCurSize(const SVal& location, uint64_t& size, CheckerContext& C) const;
		void reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void NotMatchTypePointerAccessChecker::checkLocation(const SVal& location, bool isLoad, const Stmt* S, CheckerContext& C) const
	{
		if (isLoad || !S)
			return;

		auto MR = location.getAsRegion();
		if (!MR)
			return;

		uint64_t OriginSize = 0;
		if (!getOriginSize(MR, OriginSize, C))
			return;

		uint64_t CurSize = 0;
		if (!getCurSize(location, CurSize, C))
			return;

		if (CurSize > OriginSize) {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			}

			reportBug(FD, S->getBeginLoc(), C.getBugReporter());
		}
	}

	bool NotMatchTypePointerAccessChecker::getOriginSize(const MemRegion* MR, uint64_t& Size, CheckerContext& C) const {
		if (auto VR = dyn_cast<VarRegion>(MR)) {
			if (auto VD = VR->getDecl()) {
				Size = C.getASTContext().getTypeSize(VD->getType());
				return true;
			}
		}
		else if (auto ER = dyn_cast<ElementRegion>(MR)) {
			if (auto SR = ER->getSuperRegion()) {
				if (auto VR = dyn_cast<VarRegion>(SR)) {
					if (auto VD = VR->getDecl()) {
						if (auto AT = dyn_cast<ArrayType>(VD->getType())) {
							Size = C.getASTContext().getTypeSize(AT->getElementType());
							return true;
						}
						else if (auto PT = dyn_cast<PointerType>(VD->getType())) {
							Size = C.getASTContext().getTypeSize(PT->getPointeeType());
							return true;
						}
						else if (auto BT = dyn_cast<BuiltinType>(VD->getType())) {
							Size = C.getASTContext().getTypeSize(VD->getType());
							return true;
						}
					}
				}
			}
		}

		return false;
	}

	bool NotMatchTypePointerAccessChecker::getCurSize(const SVal& location, uint64_t& Size, CheckerContext& C) const {
		 auto QT = location.getType(C.getASTContext());
		 if (auto AT = dyn_cast<ArrayType>(QT)) {
			 Size = C.getASTContext().getTypeSize(AT->getElementType());
			 return true;
		 }
		 else if (auto PT = dyn_cast<PointerType>(QT)) {
			 Size = C.getASTContext().getTypeSize(PT->getPointeeType());
			 return true;
		 }

		 return false;
	}

	void NotMatchTypePointerAccessChecker::reportBug(const FunctionDecl* FD, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "NotMatchTypePointerAccessChecker"));
		}

		// Report the issue
		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg = ls->parseMsgs(anzulocalization::NotMatchTypePointerAccessChecker, lang);        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "NotMatchTypePointerAccessChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerNotMatchTypePointerAccessChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<NotMatchTypePointerAccessChecker>();
}

bool ento::shouldRegisterNotMatchTypePointerAccessChecker(const CheckerManager& mgr) {
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
	registry.addChecker<NotMatchTypePointerAccessChecker>("anzu.NotMatchTypePointerAccessChecker", "", "");
}

#endif