#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"
#include <list>
#include <unordered_set>

using namespace clang;
using namespace ento;

namespace {
	class RedefinitionInInnerBlockVisitor : public RecursiveASTVisitor<RedefinitionInInnerBlockVisitor> {
	private:
		std::list<std::string> VarIIs_;
		std::unordered_set<VarDecl*> ReDefineVars_;

	public:
		const std::unordered_set<VarDecl*>& GetReDefineVars() const {
			return ReDefineVars_;
		}

	public:
		bool VisitVarDecl(VarDecl* VD) {
			if (!VD->isLocalVarDecl()) return true;

			if (isa<ParmVarDecl>(VD)) return true;

			auto II = VD->getIdentifier();
			if (!II) return true;
			auto Name = ToLower(II->getName().str());

			if (std::find(VarIIs_.begin(), VarIIs_.end(), Name) != VarIIs_.end()) {
				ReDefineVars_.insert(VD);
			}
			else {
				VarIIs_.push_back(Name);
			}

			return true;
		}

		bool TraverseCompoundStmt(CompoundStmt* CS) {
			auto size = VarIIs_.size();

			auto r = RecursiveASTVisitor<RedefinitionInInnerBlockVisitor>::TraverseCompoundStmt(CS);

			auto it = VarIIs_.end();
			for (auto count = (int)VarIIs_.size() - (int)size; count > 0; --count) --it;
			if (it != VarIIs_.end()) VarIIs_.erase(it, VarIIs_.end());

			return r;
		}

		bool TraverseIfStmt(IfStmt* IS) {
			auto size = VarIIs_.size();

			auto r = RecursiveASTVisitor<RedefinitionInInnerBlockVisitor>::TraverseIfStmt(IS);

			auto it = VarIIs_.end();
			for (auto count = (int)VarIIs_.size() - (int)size; count > 0; --count) --it;
			if (it != VarIIs_.end()) VarIIs_.erase(it, VarIIs_.end());

			return r;
		}

		bool TraverseWhileStmt(WhileStmt* WS) {
			auto size = VarIIs_.size();

			auto r = RecursiveASTVisitor<RedefinitionInInnerBlockVisitor>::TraverseWhileStmt(WS);

			auto it = VarIIs_.end();
			for (auto count = (int)VarIIs_.size() - (int)size; count > 0; --count) --it;
			if (it != VarIIs_.end()) VarIIs_.erase(it, VarIIs_.end());

			return r;
		}

		bool TraverseDoStmt(DoStmt* DS) {
			auto size = VarIIs_.size();

			auto r = RecursiveASTVisitor<RedefinitionInInnerBlockVisitor>::TraverseDoStmt(DS);

			auto it = VarIIs_.end();
			for (auto count = (int)VarIIs_.size() - (int)size; count > 0; --count) --it;
			if (it != VarIIs_.end()) VarIIs_.erase(it, VarIIs_.end());

			return r;
		}

		bool TraverseForStmt(ForStmt* FS) {
			auto size = VarIIs_.size();

			auto r = RecursiveASTVisitor<RedefinitionInInnerBlockVisitor>::TraverseForStmt(FS);

			auto it = VarIIs_.end();
			for (auto count = (int)VarIIs_.size() - (int)size; count > 0; --count) --it;
			if (it != VarIIs_.end()) VarIIs_.erase(it, VarIIs_.end());

			return r;
		}
	};

	class CaseSensitiveChecker
		: public Checker<check::ASTCodeBody>,
		public RecursiveASTVisitor<CaseSensitiveChecker> {
		mutable std::unique_ptr<BugType> BT;

	public:
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr,
			BugReporter& BR) const {
			if (Mgr.getASTContext().HasSyntaxErrors()) {
				return;
			}
			auto FD = dyn_cast<FunctionDecl>(D);
			RedefinitionInInnerBlockVisitor Visitor;
			Visitor.TraverseDecl(const_cast<Decl*>(D));
			auto Vars = Visitor.GetReDefineVars();
			auto ls = anzulocalization::LocaleSetting::getInstance();
			uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
			std::string Msg = ls->parseMsgs(anzulocalization::CaseSensitiveChecker, lang);
			for (auto V : Vars) {
				reportBug(FD, Msg, V->getBeginLoc(), BR);
			}
		}

	private:

		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
			if (!BT) {
				BT.reset(new BuiltinBug(
					this, "CaseSensitiveChecker"));
			}

			// Report the issue        
			PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
			auto Report = std::make_unique<BasicBugReport>(
				*BT, Msg, createRuleExtData(1, "CaseSensitiveChecker"), DLoc);
			Report->setDeclWithIssue(FD);
			BR.emitReport(std::move(Report));
		}
	};
} // end anonymous namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerCaseSensitiveChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<CaseSensitiveChecker>();
}

bool ento::shouldRegisterCaseSensitiveChecker(const CheckerManager& mgr) {
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
	registry.addChecker<CaseSensitiveChecker>("anzu1.CaseSensitiveChecker", "Prohibit variables that differ only by case", "");
}

#endif