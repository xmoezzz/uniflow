#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
	const char DefaultIgnoredIntegerValues[] = "1;2;3;4;";
	const char DefaultIgnoredFloatingPointValues[] = "1.0;100.0;";

	class MagicNumbersChecker : public Checker<check::ASTCodeBody> {
	public:
		mutable std::unique_ptr<BuiltinBug> BT;

		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, const std::string& Msg, BugReporter& BR) const;
	};

	class FindMagicNumbersVisitor : public RecursiveASTVisitor<FindMagicNumbersVisitor> {
	private:
		const FunctionDecl* FD;
		const MagicNumbersChecker& Checker;
		BugReporter& BR;
		const SourceManager* SM;
		ASTContext* AST;

		constexpr static unsigned SensibleNumberOfMagicValueExceptions = 16;

		constexpr static llvm::APFloat::roundingMode DefaultRoundingMode =
			llvm::APFloat::rmNearestTiesToEven;

		llvm::SmallVector<int64_t, SensibleNumberOfMagicValueExceptions>
			IgnoredIntegerValues;
		llvm::SmallVector<float, SensibleNumberOfMagicValueExceptions>
			IgnoredFloatingPointValues;
		llvm::SmallVector<double, SensibleNumberOfMagicValueExceptions>
			IgnoredDoublePointValues;

		const bool IgnoreBitFieldsWidths = true;
		const bool IgnorePowersOf2IntegerValues = true;

	public:
		FindMagicNumbersVisitor(const FunctionDecl* FD, const MagicNumbersChecker& checker, BugReporter& BR) : FD(FD), Checker(checker), BR(BR) {
			SM = &BR.getSourceManager();
			AST = &BR.getContext();

			const std::vector<StringRef> IgnoredIntegerValuesInput =
				parseStringList(DefaultIgnoredIntegerValues);
			IgnoredIntegerValues.resize(IgnoredIntegerValuesInput.size());
			llvm::transform(IgnoredIntegerValuesInput, IgnoredIntegerValues.begin(),
				[](StringRef Value) {
					int64_t Res;
					Value.getAsInteger(10, Res);
					return Res;
				});
			llvm::sort(IgnoredIntegerValues);


			const std::vector<StringRef> IgnoredFloatingPointValuesInput =
				parseStringList(DefaultIgnoredFloatingPointValues);
			IgnoredFloatingPointValues.reserve(IgnoredFloatingPointValuesInput.size());
			IgnoredDoublePointValues.reserve(IgnoredFloatingPointValuesInput.size());
			for (const auto& InputValue : IgnoredFloatingPointValuesInput) {
				llvm::APFloat FloatValue(llvm::APFloat::IEEEsingle());
				auto StatusOrErr =
					FloatValue.convertFromString(InputValue, DefaultRoundingMode);
				assert(StatusOrErr && "Invalid floating point representation");
				consumeError(StatusOrErr.takeError());
				IgnoredFloatingPointValues.push_back(FloatValue.convertToFloat());

				llvm::APFloat DoubleValue(llvm::APFloat::IEEEdouble());
				StatusOrErr =
					DoubleValue.convertFromString(InputValue, DefaultRoundingMode);
				assert(StatusOrErr && "Invalid floating point representation");
				consumeError(StatusOrErr.takeError());
				IgnoredDoublePointValues.push_back(DoubleValue.convertToDouble());
			}
			llvm::sort(IgnoredFloatingPointValues);
			llvm::sort(IgnoredDoublePointValues);
		}

		bool VisitIntegerLiteral(const IntegerLiteral* IL) {
			checkBoundMatch(IL);
			return true;
		}

		bool VisitFloatingLiteral(const FloatingLiteral* FL) {
			checkBoundMatch(FL);
			return true;
		}

		template <typename L>
		void checkBoundMatch(const L* MatchedLiteral) {
			if (!MatchedLiteral)
				return;

			if (SM->isMacroBodyExpansion(
				MatchedLiteral->getLocation()))
				return;

			if (isIgnoredValue(MatchedLiteral))
				return;

			if (isConstant(*MatchedLiteral))
				return;

			if (isSyntheticValue(MatchedLiteral))
				return;

			if (isBitFieldWidth(*MatchedLiteral))
				return;

			const StringRef LiteralSourceText = Lexer::getSourceText(
				CharSourceRange::getTokenRange(MatchedLiteral->getSourceRange()),
				*SM,
				BR.getContext().getLangOpts());
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string fmt = ls->parseMsgs(anzulocalization::MagicNumbersChecker, lang);
			std::string lst = LiteralSourceText.str();
			std::string Msg = std::vformat(fmt, std::make_format_args(lst));
			Checker.reportBug(FD, MatchedLiteral->getLocation(), Msg, BR);
		}

		bool isConstant(const Expr& ExprResult) const {
			return llvm::any_of(
				AST->getParents(ExprResult),
				[this](const DynTypedNode& Parent) {
					if (isUsedToInitializeAConstant(Parent))
						return true;

					// Ignore this instance, because this matches an
					// expanded class enumeration value.
					if (Parent.get<CStyleCastExpr>() &&
						llvm::any_of(
							AST->getParents(Parent),
							[](const DynTypedNode& GrandParent) {
								return GrandParent.get<SubstNonTypeTemplateParmExpr>() !=
									nullptr;
							}))
						return true;

							// Ignore this instance, because this match reports the
							// location where the template is defined, not where it
							// is instantiated.
							if (Parent.get<SubstNonTypeTemplateParmExpr>())
								return true;

							// Don't warn on string user defined literals:
							// std::string s = "Hello World"s;
							if (const auto* UDL = Parent.get<UserDefinedLiteral>())
								if (UDL->getLiteralOperatorKind() == UserDefinedLiteral::LOK_String)
									return true;

							return false;
				});
		}


		bool isIgnoredValue(const IntegerLiteral* Literal) const {
			const llvm::APInt IntValue = Literal->getValue();
			const int64_t Value = IntValue.getZExtValue();
			if (Value == 0)
				return true;

			if (IgnorePowersOf2IntegerValues && IntValue.isPowerOf2())
				return true;

			return std::binary_search(IgnoredIntegerValues.begin(),
				IgnoredIntegerValues.end(), Value);
		}

		bool isIgnoredValue(const FloatingLiteral* Literal) const {
			const llvm::APFloat FloatValue = Literal->getValue();
			if (FloatValue.isZero())
				return true;

			if (&FloatValue.getSemantics() == &llvm::APFloat::IEEEsingle()) {
				const float Value = FloatValue.convertToFloat();
				return std::binary_search(IgnoredFloatingPointValues.begin(),
					IgnoredFloatingPointValues.end(), Value);
			}

			if (&FloatValue.getSemantics() == &llvm::APFloat::IEEEdouble()) {
				const double Value = FloatValue.convertToDouble();
				return std::binary_search(IgnoredDoublePointValues.begin(),
					IgnoredDoublePointValues.end(), Value);
			}

			return false;
		}

		template<typename L>
		bool isSyntheticValue(const L* Literal) const {
			const std::pair<FileID, unsigned> FileOffset =
				SM->getDecomposedLoc(Literal->getLocation());
			if (FileOffset.first.isInvalid())
				return false;

			const StringRef BufferIdentifier =
				SM->getBufferOrFake(FileOffset.first).getBufferIdentifier();

			return BufferIdentifier.empty();
		}

		template<typename L>
		bool isBitFieldWidth(const L& Literal) const {
			return IgnoreBitFieldsWidths &&
				llvm::any_of(AST->getParents(Literal),
					[this](const DynTypedNode& Parent) {
						return isUsedToDefineABitField(Parent);
					});
		}

		bool isUsedToDefineABitField(const DynTypedNode& Node) const {
			const auto* AsFieldDecl = Node.get<FieldDecl>();
			if (AsFieldDecl && AsFieldDecl->isBitField())
				return true;

			return llvm::any_of(AST->getParents(Node),
				[this](const DynTypedNode& Parent) {
					return isUsedToDefineABitField(Parent);
				});
		}

		bool isUsedToInitializeAConstant(const DynTypedNode& Node) const {

			const auto* AsDecl = Node.get<DeclaratorDecl>();
			if (AsDecl) {
				if (AsDecl->getType().isConstQualified())
					return true;

				return AsDecl->isImplicit();
			}

			if (Node.get<EnumConstantDecl>())
				return true;

			return llvm::any_of(AST->getParents(Node),
				[this](const DynTypedNode& Parent) {
					return isUsedToInitializeAConstant(Parent);
				});
		}
	};

	void MagicNumbersChecker::checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const {
		if (Mgr.getSourceManager().isInSystemHeader(D->getBeginLoc()))
			return;

		auto FD = dyn_cast<FunctionDecl>(D);
		if (!FD)
			return;

		auto Body = FD->getBody();
		if (!Body)
			return;

		FindMagicNumbersVisitor Visitor(FD, *this, BR);
		Visitor.TraverseStmt(const_cast<Stmt*>(Body));
	}

	void MagicNumbersChecker::reportBug(const Decl* FD, const SourceLocation& Loc, const std::string& Msg, BugReporter& BR) const {
		if (Loc.isMacroID())
			return;

		if (!BT)
			BT.reset(new BuiltinBug(this, "MagicNumbersChecker"));

		// Report the issue        
		PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
		auto Report = std::make_unique<BasicBugReport>(
			*BT, Msg, createRuleExtData(1, "MagicNumbersChecker"), DLoc);
		Report->setDeclWithIssue(FD);
		BR.emitReport(std::move(Report));
	}

} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMagicNumbersChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<MagicNumbersChecker>();
}

bool ento::shouldRegisterMagicNumbersChecker(const CheckerManager& mgr) {
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
	registry.addChecker<MagicNumbersChecker>("anzu.MagicNumbersChecker", "", "");
}

#endif
