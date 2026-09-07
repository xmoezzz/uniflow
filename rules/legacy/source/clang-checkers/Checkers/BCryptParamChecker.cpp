#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Expr.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "../Utils.h"
#include <unordered_map>

using namespace clang;
using namespace ento;

namespace {
	struct BcryptData {
		const Expr* HandleExpr{ nullptr };
		const Expr* ModeExpr{ nullptr };
		std::string ModeValue;

		bool operator==(const BcryptData& Other) const {
			return HandleExpr == Other.HandleExpr && ModeExpr == Other.ModeExpr && ModeValue == Other.ModeValue;
		}

		void Profile(llvm::FoldingSetNodeID& ID) const {
			ID.AddPointer(HandleExpr);
			ID.AddPointer(ModeExpr);
			ID.AddString(ModeValue);
		}
	};

	struct BcryptModeData
	{
		uint64_t Start{ 0 };
		uint64_t End{ 0 };
	};

	std::unordered_map<std::string, BcryptModeData> BcryptModeDatas
	{
		{"DH", {512, 4096}},
		{"DSA", {512, 3072}},
		{"ECDH_P256", {256 , 256}},
		{"ECDH_P384", {384 , 384}},
		{"ECDH_P521", {521 , 521}},
		{"ECDSA_P256", {256 , 256}},
		{"ECDSA_P384", {384 , 384}},
		{"ECDSA_P521", {521, 521}},
		{"RSA", {512, 16384}},
	};

	class BCryptParamChecker : public Checker<check::PreCall,
		check::PostCall,
		check::DeadSymbols> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreCall(const CallEvent& Call, CheckerContext& C) const;
		void checkPostCall(const CallEvent& Call, CheckerContext& C) const;
		void checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const;

	private:
		void reportBug(CheckerContext& C, const std::string& Msg) const;
	};

} // end anonymous namespace

REGISTER_MAP_WITH_PROGRAMSTATE(BcryptStatus, SymbolRef, BcryptData)

void BCryptParamChecker::checkPreCall(const CallEvent& Call, CheckerContext& C) const {
	if (auto D = Call.getDecl()) {
		if (auto FD = dyn_cast<FunctionDecl>(D)) {
			auto FName = FD->getNameAsString();

			if (4 == FD->getNumParams() &&
				"BCryptGenerateKeyPair" == FName) {
				auto HandleExpr = Call.getArgExpr(0);
				auto ModeExpr = Call.getArgExpr(2);
				if (HandleExpr && ModeExpr) {
					if (auto HandleSym = Call.getArgSVal(0).getAsSymbol()) {
						if (auto Data = C.getState()->get<BcryptStatus>(HandleSym)) {
							llvm::APInt ModeValue;
							if (getIntergerConstant(ModeExpr, ModeValue)) {
								uint64_t Value = ModeValue.getZExtValue();

								auto It = BcryptModeDatas.find(Data->ModeValue);
								auto ls = anzulocalization::LocaleSetting::getInstance();
								uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());   
								if (It != BcryptModeDatas.end()) {
									if (It->second.Start == It->second.End) {
										if (It->second.Start != Value) {
											std::string fmt = ls->parseMsgs(anzulocalization::BCryptParamChecker, lang, 0);
											std::string start = std::to_string(It->second.Start);
											std::string Msg = std::vformat(fmt, std::make_format_args(start));
											reportBug(C, Msg);
										}
									}
									else {
										if (Value < It->second.Start || Value > It->second.End || (Value % 64 != 0)) {
											std::string start = std::to_string(It->second.Start);
											std::string end = std::to_string(It->second.End);
											std::string fmt = ls->parseMsgs(anzulocalization::BCryptParamChecker, lang, 1);
											std::string Msg = std::vformat(fmt, std::make_format_args(start, end));
											reportBug(C, Msg);
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

void BCryptParamChecker::checkPostCall(const CallEvent& Call, CheckerContext& C) const {
	if (auto D = Call.getDecl()) {
		if (auto FD = dyn_cast<FunctionDecl>(D)) {
			auto FName = FD->getNameAsString();

			if (4 == FD->getNumParams() &&
				"BCryptOpenAlgorithmProvider" == FName) {
				auto HandleExpr = Call.getArgExpr(0);
				auto ModeExpr = Call.getArgExpr(1);
				if (HandleExpr && ModeExpr) {
					if (auto HandleLocVal = Call.getArgSVal(0).getAs<Loc>()) {
						auto State = C.getState();
						if (auto HandleSym = State->getSVal(*HandleLocVal).getAsSymbol()) {
							std::string ModeValue;
							if (getStringConstant(ModeExpr->IgnoreParenCasts(), ModeValue)) {
								State = State->set<BcryptStatus>(HandleSym, BcryptData{ HandleExpr, ModeExpr, ModeValue });
								C.addTransition(State);
							}
						}
					}
				}
			}
		}
	}
}

void BCryptParamChecker::checkDeadSymbols(SymbolReaper& SymReaper, CheckerContext& C) const {
	auto State = C.getState();
	auto Pointers = State->get<BcryptStatus>();
	bool AddState = false;
	for (auto& Pointer : Pointers) {
		auto Sym = Pointer.first;
		bool IsSymDead = SymReaper.isDead(Sym);
		if (IsSymDead) {
			State = State->remove<BcryptStatus>(Sym);
			AddState = true;
		}
	}

	if (AddState) {
		C.addTransition(State);
	}
}

void BCryptParamChecker::reportBug(CheckerContext& C, const std::string& Msg) const {
	if (ExplodedNode* N = C.generateNonFatalErrorNode()) {
		if (!BT)
			BT.reset(new BuiltinBug(this, "BCryptParamChecker"));

		auto R = std::make_unique<PathSensitiveBugReport>(*BT, createRuleExtData(1, "BCryptParamChecker"), Msg, N);
		C.emitReport(std::move(R));
	}
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerBCryptParamChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<BCryptParamChecker>();
}

bool ento::shouldRegisterBCryptParamChecker(const CheckerManager& mgr) {
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
	registry.addChecker<BCryptParamChecker>("anzu.BCryptParamChecker", "", "");
}

#endif
