#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/FormatString.h"
#include "clang/Basic/TargetInfo.h"

#include "../Utils.h"
#include <unordered_map>

using namespace clang;
using namespace ento;

namespace {
	std::unordered_map<std::string, int> FormatFunc =
	{
		{"printf", 0},
		{"fprintf", 1},
		{"sprintf", 1},
		{"snprintf", 2},
	};

	class FormatSpecifierTypeMismatchChecker : public Checker<check::PreStmt<CallExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
			const FunctionDecl* FD = C.getCalleeDecl(CE);
			if (!FD || !FD->isExternC())
				return;

			auto FuncName = FD->getNameAsString();
			auto It = FormatFunc.find(FuncName);
			if (It == FormatFunc.end())
				return;

			if (CE->getNumArgs() <= It->second)
				return;

			const Expr* FormatArg = CE->getArg(It->second);
			if (!FormatArg)
				return;

			const StringLiteral* StrLit = llvm::dyn_cast_or_null<StringLiteral>(FormatArg->IgnoreParenCasts());
			if (!StrLit)
				return;


			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::FormatSpecifierTypeMismatchChecker, lang);
			ASTContext& Ctx = C.getASTContext();
			const TargetInfo& Target = Ctx.getTargetInfo();
			auto&& ArgType = Utils::parseFormatString(StrLit->getString().str());
			for (unsigned i = 0; i < ArgType.size(); ++i) {
				auto ArgIdx = It->second + i + 1;
				if (ArgIdx >= CE->getNumArgs()) {
					break;
				}

				if (auto ArgExpr = CE->getArg(ArgIdx))
				{
					QualType ArgTy = ArgExpr->getType();
					bool IsEqual = false;
					switch (ArgType[i].specifier) {
					case FormatSpecifier::CHAR:
						IsEqual = ArgTy->isCharType();
						break;

					case FormatSpecifier::FLOAT:
						IsEqual = ArgTy->isFloatingType();
						break;

					case FormatSpecifier::INT:
						IsEqual = ArgTy->isSignedIntegerType();
						break;

					case FormatSpecifier::UINT:
						IsEqual = ArgTy->isUnsignedIntegerType();
						break;

					case FormatSpecifier::HEX:
						IsEqual = ArgTy->isIntegerType() || ArgTy->isPointerType();
						break;

					case FormatSpecifier::OCTAL:
						IsEqual = ArgTy->isIntegerType();
						break;

					case FormatSpecifier::STRING:
						IsEqual = ArgTy->isPointerType() || ArgTy->isArrayType();
						break;

					case FormatSpecifier::EXP:
						IsEqual = ArgTy->isFloatingType() || ArgTy->isIntegerType();
						break;

					default:
						IsEqual = true;
						break;
					}

					if (!IsEqual)
					{
						const FunctionDecl* FD = nullptr;
						if (auto ADC = C.getCurrentAnalysisDeclContext()) {
							FD = dyn_cast<FunctionDecl>(ADC->getDecl());
						}
						reportBug(FD, Msg, ArgExpr->getBeginLoc(), C.getBugReporter());
					}
				}
			}
		}

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "FormatSpecifierTypeMismatchChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "FormatSpecifierTypeMismatchChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
}


/// Checker registration
#if RELEASE_BUNDLE
void ento::registerFormatSpecifierTypeMismatchChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<FormatSpecifierTypeMismatchChecker>();
}

bool ento::shouldRegisterFormatSpecifierTypeMismatchChecker(const CheckerManager& mgr) {
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
	registry.addChecker<FormatSpecifierTypeMismatchChecker>("anzu.FormatSpecifierTypeMismatchChecker", "", "");
}

#endif