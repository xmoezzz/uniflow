#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {
	std::unordered_set<std::string> FunctionSet = {
		"isalnum", "isalpha", "isascii", "isblank",
		"iscntrl", "isdigit", "isgraph", "islower",
		"isprint", "ispunct", "isspace", "isupper",
		"isxdigit", "toascii", "toupper", "tolower"
	};

	class CharCastIntChecker : public Checker<check::ASTDecl<VarDecl>, check::PreStmt<BinaryOperator>, check::PreStmt<CallExpr>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkASTDecl(const VarDecl* VD, AnalysisManager& mgr, BugReporter& BR) const {
			if (!checkType(VD->getType(), VD->getInit(), mgr.getASTContext())) {
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::CharCastIntChecker, lang, 0);
				reportBug(findFunctionDecl(VD),
					Msg,
					createRuleExtData(1, "CharCastIntChecker.1"),
					VD->getInit()->getBeginLoc(),
					BR);
			}
		}

		void checkPreStmt(const BinaryOperator* B, CheckerContext& C) const {
			if (B->getOpcode() != BinaryOperator::Opcode::BO_Assign)
				return;

			if (!checkType(B->getLHS()->getType(), B->getRHS(), C.getASTContext())) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::CharCastIntChecker, lang, 0);
				reportBug(FD, Msg, createRuleExtData(1, "CharCastIntChecker.1"),
					B->getRHS()->getBeginLoc(), C.getBugReporter());
			}
		}

		void checkPreStmt(const CallExpr* CE, CheckerContext& C) const {
			if (!CE)
				return;

			auto FD = CE->getDirectCallee();
			if (!FD)
				return;

			if (FunctionSet.find(FD->getNameAsString()) == FunctionSet.end())
				return;

			if (FD->getNumParams() == 0)
				return;

			auto PD = FD->getParamDecl(0);
			if (!PD)
				return;

			if (CE->getNumArgs() == 0)
				return;

			if (!checkTypeWithParam(PD->getType(), CE->getArg(0), C.getASTContext())) {
				const FunctionDecl* FD = nullptr;
				if (auto ADC = C.getCurrentAnalysisDeclContext()) {
					FD = dyn_cast<FunctionDecl>(ADC->getDecl());
				}
				auto ls = anzulocalization::LocaleSetting::getInstance();
				uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
				std::string Msg = ls->parseMsgs(anzulocalization::CharCastIntChecker, lang, 1);
				reportBug(FD, Msg, createRuleExtData(1, "CharCastIntChecker.2"),
					CE->getArg(0)->getBeginLoc(), C.getBugReporter());
			}
		}

		bool checkType(const QualType& LHSType, const Expr* RHS, ASTContext& AST) const {
			if (!LHSType->isIntegerType() || !RHS) {
				return true;
			}

			auto RHSType = RHS->IgnoreParenImpCasts()->getType();
			if (auto BT = dyn_cast<BuiltinType>(RHSType)) {
				if (BT->getKind() == BuiltinType::Char_S ||
					BT->getKind() == BuiltinType::SChar) {
					if (AST.getTypeSize(LHSType) > AST.getTypeSize(RHSType) &&
						!LHSType->isAnyCharacterType()) {
						return false;
					}
				}
			}

			return true;
		}

		bool checkTypeWithParam(const QualType& LHSType, const Expr* RHS, ASTContext& AST) const {
			auto LHSBT = dyn_cast<BuiltinType>(LHSType);
			if (!LHSBT)
				return true;

			if (LHSBT->getKind() != BuiltinType::Char_U &&
				LHSBT->getKind() != BuiltinType::UChar)
				return true;

			auto RHSType = RHS->IgnoreParenImpCasts()->getType();
			if (auto BT = dyn_cast<BuiltinType>(RHSType)) {
				if (BT->getKind() == BuiltinType::Char_S ||
					BT->getKind() == BuiltinType::SChar) {
					return false;
				}
			}

			return true;
		}

		void reportBug(const Decl* FD, const std::string& Msg, const std::string& RuleID, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT)
				BT.reset(new BuiltinBug(this, "CharCastIntChecker"));

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT,
				Msg,
				RuleID,
				DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}

	};
		} // namespace

		/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCharCastIntChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CharCastIntChecker>();
}

bool ento::shouldRegisterCharCastIntChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CharCastIntChecker>("anzu1.CharCastIntChecker", "", "");
}

#endif
