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
	class FindConstVarDeclVisitor
		: public RecursiveASTVisitor<FindConstVarDeclVisitor> {
		std::list<const VarDecl*> DeclList;

	public:
		const std::list<const VarDecl*>& getDecls() {
			return DeclList;
		}

	public:
		bool VisitVarDecl(const VarDecl* VD) {
			if (VD) {
				DeclList.push_back(VD);
			}
			return true;
		}
	};

	class ConstVarWriteOpChecker : public Checker<check::Location> {
		mutable std::unique_ptr<BuiltinBug> BT;
		mutable std::unordered_map<const LocationContext*, std::vector<const MemRegion*>> ConstInfos;

	public:
		void checkLocation(const SVal& location, bool isLoad, const Stmt* S, CheckerContext& C) const;
		bool isStringRegion(CheckerContext& C, const MemRegion* MR) const;
		bool GetConstInfos(CheckerContext& C, std::vector<const MemRegion*>*& Infos) const;
		bool IsConstVar(const VarDecl* VD) const;
		bool IsConstPtrVar(const VarDecl* VD) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const std::string& RuleId, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void ConstVarWriteOpChecker::checkLocation(const SVal& location, bool isLoad, const Stmt* S, CheckerContext& C) const
	{
		if (isLoad || !S)
			return;

		auto R = location.getAsRegion();
		if (!R)
			return;

		auto ls = anzulocalization::LocaleSetting::getInstance();
		uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
		std::string Msg1 = ls->parseMsgs(anzulocalization::ConstVarWriteOpChecker, lang, 0);
		std::string Msg2 = ls->parseMsgs(anzulocalization::ConstVarWriteOpChecker, lang, 1);
		if (isStringRegion(C, R)) {
			const FunctionDecl* FD = nullptr;
			if (auto ADC = C.getCurrentAnalysisDeclContext()) {
				FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			} 
			reportBug(FD, Msg1,
				createRuleExtData(1, "ConstVarWriteOpChecker.1"),
				S->getBeginLoc(), C.getBugReporter());
			return;
		}

		std::vector<const MemRegion*>* Infos = nullptr;
		if (GetConstInfos(C, Infos) && Infos) {
			for (auto MR : *Infos) {
				if (R == MR) {
					const FunctionDecl* FD = nullptr;
					if (auto ADC = C.getCurrentAnalysisDeclContext()) {
						FD = dyn_cast<FunctionDecl>(ADC->getDecl());
					}
					reportBug(FD,
						Msg2, createRuleExtData(1, "ConstVarWriteOpChecker.2"),
						S->getBeginLoc(), C.getBugReporter());
					break;
				}
			}
		}
	}

	bool ConstVarWriteOpChecker::isStringRegion(CheckerContext& C, const MemRegion* MR) const {
		if (!MR)
			return false;

		if (auto ER = dyn_cast<ElementRegion>(MR)) {
			if (auto SR = ER->getSuperRegion()) {
				return isa<StringRegion>(SR);
			}
		}

		return false;
	}

	bool ConstVarWriteOpChecker::GetConstInfos(CheckerContext& C, std::vector<const MemRegion*>*& Infos) const {
		auto LC = C.getLocationContext();
		if (!LC)
			return false;

		auto It = ConstInfos.find(LC);
		if (It != ConstInfos.end()) {
			Infos = &It->second;
			return true;
		}

		ConstInfos[LC];
		It = ConstInfos.find(LC);
		Infos = &It->second;

		const FunctionDecl* FD = nullptr;
		if (auto ADC = C.getCurrentAnalysisDeclContext()) {
			FD = dyn_cast<FunctionDecl>(ADC->getDecl());
			if (FD) {
				auto State = C.getState();
				for (auto PVD : FD->parameters()) {
					if (IsConstPtrVar(PVD)) {
						auto Val = State->getLValue(PVD, C.getLocationContext());
						auto RefVal = State->getSVal(Val);
						if (auto MR = RefVal.getAsRegion()) {
							It->second.push_back(MR);
						}
					}
				}

				FindConstVarDeclVisitor Visitor;
				Visitor.TraverseDecl(const_cast<FunctionDecl*>(FD));
				auto Decls = Visitor.getDecls();
				for (auto VD : Decls) {
					if (IsConstVar(VD)) {
						auto Val = State->getLValue(VD, C.getLocationContext());
						if (auto MR = Val.getAsRegion()) {
							It->second.push_back(MR);
						}
					}
				}
			}
		}

		return true;
	}

	bool ConstVarWriteOpChecker::IsConstVar(const VarDecl* VD) const {
		if (!VD)
			return false;

		return VD->getType().isConstQualified();
	}

	bool ConstVarWriteOpChecker::IsConstPtrVar(const VarDecl* VD) const {
		if (!VD)
			return false;

		auto QT = VD->getType();
		if (0 && QT->isReferenceType()) {
			return QT->getPointeeType().isConstQualified();
		}

		if (QT->isPointerType()) {
			return QT->getPointeeType().isConstQualified();
		}

		return false;
	}

	void ConstVarWriteOpChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const std::string& RuleId, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT) {
			BT.reset(new BuiltinBug(
				this, "ConstVarWriteOpChecker"));
		}

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, RuleId, DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerConstVarWriteOpChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ConstVarWriteOpChecker>();
}

bool ento::shouldRegisterConstVarWriteOpChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ConstVarWriteOpChecker>("anzu.ConstVarWriteOpChecker", "", "");
}

#endif