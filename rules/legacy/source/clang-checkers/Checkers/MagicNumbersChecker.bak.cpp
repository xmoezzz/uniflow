#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/ASTMatchers/ASTMatchFinder.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;
using namespace ast_matchers;

namespace {
	const char DefaultIgnoredIntegerValues[] = "1;2;3;4;";
	const char DefaultIgnoredFloatingPointValues[] = "1.0;100.0;";

	bool isUsedToInitializeAConstant(const MatchFinder::MatchResult& Result,
		const DynTypedNode& Node) {

		const auto* AsDecl = Node.get<DeclaratorDecl>();
		if (AsDecl) {
			if (AsDecl->getType().isConstQualified())
				return true;

			return AsDecl->isImplicit();
		}

		if (Node.get<EnumConstantDecl>())
			return true;

		return llvm::any_of(Result.Context->getParents(Node),
			[&Result](const DynTypedNode& Parent) {
				return isUsedToInitializeAConstant(Result, Parent);
			});
	}

	bool isUsedToDefineABitField(const MatchFinder::MatchResult& Result,
		const DynTypedNode& Node) {
		const auto* AsFieldDecl = Node.get<FieldDecl>();
		if (AsFieldDecl && AsFieldDecl->isBitField())
			return true;

		return llvm::any_of(Result.Context->getParents(Node),
			[&Result](const DynTypedNode& Parent) {
				return isUsedToDefineABitField(Result, Parent);
			});
	}

	class MagicNumbersChecker : public Checker<check::ASTCodeBody> {
	public:
		mutable std::unique_ptr<BuiltinBug> BT;

		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, const std::string& Msg, BugReporter& BR) const;
	};

	class MagicNumbersCheckerCallback : public MatchFinder::MatchCallback {
	private:
		const FunctionDecl* FD;
		const MagicNumbersChecker& Checker;
		BugReporter& BR;

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
		MagicNumbersCheckerCallback(const FunctionDecl* FD, const MagicNumbersChecker& checker, BugReporter& BR) : FD(FD), Checker(checker), BR(BR) {
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

		virtual void run(const MatchFinder::MatchResult& Result) override {
			TraversalKindScope RAII(*Result.Context, TK_AsIs);

			checkBoundMatch<IntegerLiteral>(Result, "integer");
			checkBoundMatch<FloatingLiteral>(Result, "float");
		}

		template <typename L>
		void checkBoundMatch(const ast_matchers::MatchFinder::MatchResult& Result,
			const char* BoundName) {
			const L* MatchedLiteral = Result.Nodes.getNodeAs<L>(BoundName);
			if (!MatchedLiteral)
				return;

			if (Result.SourceManager->isMacroBodyExpansion(
				MatchedLiteral->getLocation()))
				return;

			if (isIgnoredValue(MatchedLiteral))
				return;

			if (isConstant(Result, *MatchedLiteral))
				return;

			if (isSyntheticValue(Result.SourceManager, MatchedLiteral))
				return;

			if (isBitFieldWidth(Result, *MatchedLiteral))
				return;

			const StringRef LiteralSourceText = Lexer::getSourceText(
				CharSourceRange::getTokenRange(MatchedLiteral->getSourceRange()),
				BR.getSourceManager(),
				BR.getContext().getLangOpts());
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string fmt = ls->parseMsgs(anzulocalization::HardcodedCryptoKeyChecker, lang);
			std::string Msg = std::vformat(fmt, std::make_format_args());
			Checker.reportBug(FD, MatchedLiteral->getLocation(), LiteralSourceText.str() + "is a magic number; consider replacing it with a named constant", BR);
		}

		bool isConstant(const MatchFinder::MatchResult& Result,
			const Expr& ExprResult) const {
			return llvm::any_of(
				Result.Context->getParents(ExprResult),
				[&Result](const DynTypedNode& Parent) {
					if (isUsedToInitializeAConstant(Result, Parent))
						return true;

					// Ignore this instance, because this matches an
					// expanded class enumeration value.
					if (Parent.get<CStyleCastExpr>() &&
						llvm::any_of(
							Result.Context->getParents(Parent),
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
		bool isSyntheticValue(const SourceManager* SourceManager,
			const L* Literal) const {
			const std::pair<FileID, unsigned> FileOffset =
				SourceManager->getDecomposedLoc(Literal->getLocation());
			if (FileOffset.first.isInvalid())
				return false;

			const StringRef BufferIdentifier =
				SourceManager->getBufferOrFake(FileOffset.first).getBufferIdentifier();

			return BufferIdentifier.empty();
		}

		template<typename L>
		bool isBitFieldWidth(
			const clang::ast_matchers::MatchFinder::MatchResult& Result,
			const L& Literal) const {
			return IgnoreBitFieldsWidths &&
				llvm::any_of(Result.Context->getParents(Literal),
					[&Result](const DynTypedNode& Parent) {
						return isUsedToDefineABitField(Result, Parent);
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

		MatchFinder Finder;
		MagicNumbersCheckerCallback Callback(nullptr, *this, BR);

		Finder.addMatcher(traverse(TK_AsIs, integerLiteral().bind("integer")), &Callback);
		Finder.addMatcher(traverse(TK_AsIs, floatLiteral().bind("float")), &Callback);
		Finder.match(*Body, Mgr.getASTContext());
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
	registry.addChecker<MagicNumbersChecker>("anzu1.MagicNumbersChecker", "", "");
}

#endif
