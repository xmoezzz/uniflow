#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "../Utils.h"
#include <unordered_map>
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {
	typedef std::unordered_set<std::string> VMDSet;
	typedef std::shared_ptr<VMDSet> VMDSetPtr;
	class VirtualOverrideConstFunction : public Checker<check::ASTDecl<CXXMethodDecl>> {
		mutable std::unique_ptr<BugType> BT;
		mutable std::unordered_map<const CXXRecordDecl*, VMDSetPtr> RecordVMDs;

	public:
		void checkASTDecl(const CXXMethodDecl* MD, AnalysisManager& Mgr, BugReporter& BR) const;
		void enumRecordVMDs(const CXXRecordDecl* RD, VMDSetPtr& VMDs, int MaxEnumLevel) const;
		void reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const;
	};
}

void VirtualOverrideConstFunction::checkASTDecl(const CXXMethodDecl* MD, AnalysisManager& Mgr, BugReporter& BR) const {
	if (!MD)
		return;

	auto RD = MD->getParent();
	if (!RD)
		return;

	if (!RD->hasDefinition())
		return;

	if (MD->isVirtual())
		return;

	VMDSetPtr VMDs;
	enumRecordVMDs(RD, VMDs, 10);
	
	auto Name = getFunctionNameForDeclEx(MD);
	if (Name.rfind(" const") + 6 == Name.size()) {
		Name = Name.substr(0, Name.size() - 6);
	}
	else {
		Name = Name + " const";
	}

	if (!Name.empty()) {
		auto It = VMDs->find(Name);
		if (It != VMDs->end()) {
			reportBug(RD, MD->getBeginLoc(), BR);
		}
	}

}

void VirtualOverrideConstFunction::enumRecordVMDs(const CXXRecordDecl* RD, VMDSetPtr& VMDs, int MaxEnumLevel) const {
	if (RD) {
		if (MaxEnumLevel == 0)
			return;

		auto It = RecordVMDs.find(RD);
		if (It != RecordVMDs.end()) {
			VMDs = It->second;
			return;
		}

		VMDs = std::make_shared<VMDSet>();
		RecordVMDs[RD] = VMDs;

		for (auto MD : RD->methods()) {
			if (!MD->isVirtual())
				continue;

			auto Name = getFunctionNameForDeclEx(MD);
			if (!Name.empty()) VMDs->insert(Name);
		}

		for (auto I : RD->bases()) {
			if (auto RT = I.getType()->castAs<RecordType>()) {
				if (auto RD = RT->getDecl()) {
					if (auto BRD = dyn_cast<CXXRecordDecl>(RD)) {
						VMDSetPtr BasePtr;
						enumRecordVMDs(BRD, BasePtr, MaxEnumLevel - 1);
						if (BasePtr) {
							VMDs->insert(BasePtr->begin(), BasePtr->end());
						}
					}
				}
			}
		}
	}
}

void VirtualOverrideConstFunction::reportBug(const Decl* FD, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT)
		BT.reset(new BuiltinBug(this, "VirtualOverrideConstFunction"));

	// Report the issue        
	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string Msg = ls->parseMsgs(anzulocalization::VirtualOverrideConstFunction, lang);	
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "VirtualOverrideConstFunction"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerVirtualOverrideConstFunction(CheckerManager& Mgr) {
	Mgr.registerChecker<VirtualOverrideConstFunction>();
}

bool ento::shouldRegisterVirtualOverrideConstFunction(const CheckerManager& mgr) {
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
	registry.addChecker<VirtualOverrideConstFunction>("anzu.VirtualOverrideConstFunction", "Detection of alignment error of the finger", "");
}

#endif