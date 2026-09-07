#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {

	class StructPaddingChecker : public Checker<check::PreStmt<UnaryExprOrTypeTraitExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const UnaryExprOrTypeTraitExpr* UE, CheckerContext& C) const;

	private:
		bool hasPadding(const RecordDecl* RD) const;
		void reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

	bool StructPaddingChecker::hasPadding(const RecordDecl* RD) const {
		unsigned TotalSize = 0;
		ASTContext& Ctx = RD->getASTContext();

		for (const FieldDecl* FD : RD->fields()) {
			TotalSize += Ctx.getTypeSize(FD->getType());
		}

		unsigned StructSize = Ctx.getTypeSize(Ctx.getRecordType(RD));
		return StructSize != TotalSize;
	}

	void StructPaddingChecker::checkPreStmt(const UnaryExprOrTypeTraitExpr* UE, CheckerContext& C) const {
		if (UE->getKind() != UETT_SizeOf)
			return;

		QualType Ty = UE->getTypeOfArgument();
		if (const RecordType* RT = Ty->getAs<RecordType>()) {
			if (auto D = RT->getDecl()) {
				if (const RecordDecl* RD = D->getDefinition()) {
					const RecordDecl* ParentRD = llvm::dyn_cast_or_null<RecordDecl>(RD->getDeclContext());
					if (ParentRD && hasPadding(ParentRD)) {
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}

						auto ls = anzulocalization::LocaleSetting::getInstance();
						uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
						std::string fmt = ls->parseMsgs(anzulocalization::StructPaddingChecker, lang);
						std::string rd = RD->getNameAsString();
						std::string prd = ParentRD->getNameAsString();
						std::string Msg = std::vformat(fmt, std::make_format_args(rd, prd));

						reportBug(FD, Msg, UE->getBeginLoc(), C.getBugReporter());
					}
				}
			}
		}
	}

	void StructPaddingChecker::reportBug(const FunctionDecl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;
		
		if (!BT)
			BT.reset(new BuiltinBug(this, "StructPaddingChecker"));

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "StructPaddingChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerStructPaddingChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<StructPaddingChecker>();
}

bool ento::shouldRegisterStructPaddingChecker(const CheckerManager& mgr) {
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
	registry.addChecker<StructPaddingChecker>("anzu.StructPaddingChecker", "", "");
}

#endif
