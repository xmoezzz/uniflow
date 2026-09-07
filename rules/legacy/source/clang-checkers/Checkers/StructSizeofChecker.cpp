#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class StructSizeofChecker : public Checker< check::PreStmt<ExplicitCastExpr> > {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const ExplicitCastExpr* ECE, CheckerContext& C) const;

	private:
		bool checkAllocSizeValid(const ASTContext& AST, const QualType& QT, const CallExpr* CE) const;
		const Expr* getAllocSizeExpr(const CallExpr* CE) const;
		bool getArgTypes(const Expr* E, std::vector<QualType>& QTS) const;
		bool hasPadding(const RecordDecl* RD) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

	void StructSizeofChecker::checkPreStmt(const ExplicitCastExpr* ECE, CheckerContext& C) const {
		if (auto PT = dyn_cast<PointerType>(ECE->getType())) {
			if (auto E = ECE->getSubExpr()) {
				if (auto CE = dyn_cast<CallExpr>(E)) {
					if (!checkAllocSizeValid(C.getASTContext(), PT->getPointeeType(), CE)) {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}

						auto ls = anzulocalization::LocaleSetting::getInstance();
						uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
						std::string Msg = ls->parseMsgs(anzulocalization::StructSizeofChecker, lang);
						reportBug(FD,
							Msg,
							CE->getBeginLoc(),
							C.getBugReporter());
					}
				}
			}
		}
	}

	bool StructSizeofChecker::checkAllocSizeValid(const ASTContext& AST, const QualType& QT, const CallExpr* CE) const {
		auto RT = dyn_cast<RecordType>(QT);
		if (!RT) {
			if (auto ET = dyn_cast<ElaboratedType>(QT)) {
				RT = dyn_cast<RecordType>(ET->getNamedType());
			}
		}
		if (!RT)
			return true;

		auto RD = RT->getDecl();
		if (!RD)
			return true;

		if (!hasPadding(RD))
			return true;

		auto Arg = getAllocSizeExpr(CE);
		if (!Arg)
			return true;

		std::vector<QualType> QTS;
		if (!getArgTypes(Arg, QTS))
			return true;

		if (QTS.size() <= 1)
			return true;

		for (auto F : RD->fields()) {
			if (F) {
				auto Size = AST.getTypeSize(F->getType());
				for (auto it = QTS.begin(); it != QTS.end(); ++it) {
					auto SizeUse = AST.getTypeSize(*it);
					if (Size == SizeUse) {
						QTS.erase(it);
						break;
					}
				}
			}
		}

		if (!QTS.empty())
			return true;

		return false;
	}

	const Expr* StructSizeofChecker::getAllocSizeExpr(const CallExpr* CE) const {
		if (!CE)
			return nullptr;

		auto FD = CE->getDirectCallee();
		if (!FD)
			return nullptr;

		auto Name = FD->getQualifiedNameAsString();
		if (Name != "malloc")
			return nullptr;

		if (CE->getNumArgs() != 1)
			return nullptr;

		return CE->getArg(0);
	}

	bool StructSizeofChecker::getArgTypes(const Expr* E, std::vector<QualType>& QTS) const {
		if (!E)
			return false;

		E = E->IgnoreParenCasts();
		auto UEOTTE = dyn_cast<UnaryExprOrTypeTraitExpr>(E);
		if (UEOTTE) {
			if (UEOTTE->getKind() != UETT_SizeOf)
				return false;

			QTS.push_back(UEOTTE->getTypeOfArgument());
			return true;
		}

		auto BO = dyn_cast<BinaryOperator>(E);
		if (!BO) {
			return false;
		}

		if (BO->getOpcode() != BinaryOperatorKind::BO_Add) {
			return false;
		}

		if (!getArgTypes(BO->getLHS(), QTS)) {
			return false;
		}

		if (!getArgTypes(BO->getRHS(), QTS)) {
			return false;
		}

		return true;
	}

	bool StructSizeofChecker::hasPadding(const RecordDecl* RD) const {
		unsigned TotalSize = 0;
		ASTContext& Ctx = RD->getASTContext();

		for (const FieldDecl* FD : RD->fields()) {
			TotalSize += Ctx.getTypeSize(FD->getType());
		}

		unsigned StructSize = Ctx.getTypeSize(Ctx.getRecordType(RD));
		return StructSize != TotalSize;
	}

	void StructSizeofChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "StructSizeofChecker"));

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "StructSizeofChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerStructSizeofChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<StructSizeofChecker>();
}

bool ento::shouldRegisterStructSizeofChecker(const CheckerManager& mgr) {
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
	registry.addChecker<StructSizeofChecker>("anzu.StructSizeofChecker", "", "");
}

#endif
