#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"

#include <set>

using namespace clang;
using namespace clang::ento;

namespace {
	class CharArrayInitChecker : public Checker<check::ASTDecl<VarDecl>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void analyzeInitExpr(const VarDecl* VD, const Type* T, const Expr* Init, BugReporter& BR) const;
		void reportBug(const VarDecl* VD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void CharArrayInitChecker::checkASTDecl(const VarDecl* VD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (VD) {
		if (auto Init = VD->getInit()) {
			analyzeInitExpr(VD, VD->getType().getTypePtr(), Init, BR);
		}
	}
}

void CharArrayInitChecker::analyzeInitExpr(const VarDecl* VD, const Type* T, const Expr* Init, BugReporter& BR) const {
	if (!T || !Init)
		return;

	// found char array
	if (auto CAT = dyn_cast<ConstantArrayType>(T)) {
		if (CAT->getElementType()->isCharType()) {
			if (auto SL = dyn_cast<StringLiteral>(Init)) {
				if (CAT->getSize().getLimitedValue() <= SL->getLength()) {
					// report
					reportBug(VD, SL->getBeginLoc(), BR);
				}
			}
			return;
		}
	}

	if (auto InitList = dyn_cast<InitListExpr>(Init)) {
		// array
		if (auto CAT = dyn_cast<ArrayType>(T)) {
			for (auto SubInit : InitList->inits()) {
				analyzeInitExpr(VD, CAT->getElementType().getTypePtr(), SubInit, BR);
			}
			return;
		}

		// record
		if (auto RT = dyn_cast<RecordType>(T)) {
			auto NumInits = InitList->getNumInits();
			unsigned int index = 0;
			if (auto RD = RT->getDecl()) {
				for (auto Field : RD->fields()) {
					if (index >= NumInits)
						break;

					analyzeInitExpr(VD, Field->getType().getTypePtr(), InitList->getInit(index), BR);
					++index;
				}
			}
			return;
		}

		if (auto ET = dyn_cast<ElaboratedType>(T)) {
			analyzeInitExpr(VD, ET->getNamedType().getTypePtr(), InitList, BR);
			return;
		}
	}
}

void CharArrayInitChecker::reportBug(const VarDecl* VD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "CharArrayInitChecker"));
	}
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::CharArrayInitChecker, lang);
	std::string vd = VD->getNameAsString();
	std::string Msg = std::vformat(fmt, std::make_format_args(vd));

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "CharArrayInitChecker"), DLoc);
	Report->setDeclWithIssue(findFunctionDecl(VD));
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCharArrayInitChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CharArrayInitChecker>();
}

bool ento::shouldRegisterCharArrayInitChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CharArrayInitChecker>("anzu.CharArrayInitChecker", "An array used to represent strings must be terminated with '\0'.", "");
}

#endif