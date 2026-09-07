#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace ento;

namespace {
	std::set<StringRef> ErrnoNames = {
		"EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO", "E2BIG", "ENOEXEC", "EBADF",
		"ECHILD", "EAGAIN", "ENOMEM", "EACCES", "EFAULT", "ENOTBLK", "EBUSY", "EEXIST", "EXDEV",
		"ENODEV", "ENOTDIR", "EISDIR", "EINVAL", "ENFILE", "EMFILE", "ENOTTY", "ETXTBSY", "EFBIG",
		"ENOSPC", "ESPIPE", "EROFS", "EMLINK", "EPIPE", "EDOM", "ERANGE", "EDEADLK", "ENAMETOOLONG",
		"ENOLCK", "ENOSYS", "ENOTEMPTY", "ELOOP", "ENOMSG", "EIDRM", "ECHRNG", "EL2NSYNC", "EL3HLT",
		"EL3RST", "ELNRNG", "EUNATCH", "ENOCSI", "EL2HLT", "EBADE", "EBADR", "EXFULL", "ENOANO",
			"EBADRQC", "EBADSLT", "EBFONT", "ENOSTR", "ENODATA", "ETIME", "ENOSR", "ENONET", "ENOPKG",
			"EREMOTE", "ENOLINK", "EADV", "ESRMNT", "ECOMM", "EPROTO", "EMULTIHOP", "EDOTDOT", "EBADMSG",
			"EOVERFLOW", "ENOTUNIQ", "EBADFD", "EREMCHG", "ELIBACC", "ELIBBAD", "ELIBSCN", "ELIBMAX",
			"ELIBEXEC", "EILSEQ", "ERESTART", "ESTRPIPE", "EUSERS", "ENOTSOCK", "EDESTADDRREQ", "EMSGSIZE",
			"EPROTOTYPE", "ENOPROTOOPT", "EPROTONOSUPPORT", "ESOCKTNOSUPPORT", "EOPNOTSUPP", "EPFNOSUPPORT",
			"EAFNOSUPPORT", "EADDRINUSE", "EADDRNOTAVAIL", "ENETDOWN", "ENETUNREACH", "ENETRESET",
			"ECONNABORTED", "ECONNRESET", "ENOBUFS", "EISCONN", "ENOTCONN", "ESHUTDOWN", "ETOOMANYREFS",
			"ETIMEDOUT", "ECONNREFUSED", "EHOSTDOWN", "EHOSTUNREACH", "EALREADY", "EINPROGRESS", "ESTALE",
			"EUCLEAN", "ENOTNAM", "ENAVAIL", "EISNAM", "EREMOTEIO", "EDQUOT", "ENOMEDIUM", "EMEDIUMTYPE",
			"ECANCELED", "ENOKEY", "EKEYEXPIRED", "EKEYREVOKED", "EKEYREJECTED", "EOWNERDEAD", "ENOTRECOVERABLE"
	};

	class FindReturnStmtVisitor
		: public RecursiveASTVisitor<FindReturnStmtVisitor> {
		std::list<const Expr*> ExprList;

	public:
		const std::list<const Expr*>& getExprs() {
			return ExprList;
		}

	public:
		bool VisitReturnStmt(const ReturnStmt* RS) {
			if (auto E = RS->getRetValue()) {
				ExprList.push_back(E);
			}
			return true;
		}
	};

	class ErrnoReturnTypeChecker : public Checker<check::PreStmt<ReturnStmt>> {
		mutable std::unique_ptr<BuiltinBug> BT;

	public:
		void checkPreStmt(const ReturnStmt* RS, CheckerContext& C) const;
		void checkASTCodeBody(const Decl* D, AnalysisManager& Mgr, BugReporter& BR) const;

	private:
		bool isErrnoVar(const Expr* E, CheckerContext& C) const;
		void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const;
	};

} // end anonymous namespace

void ErrnoReturnTypeChecker::checkPreStmt(const ReturnStmt* RS, CheckerContext& C) const {
	const Expr* RetVal = RS->getRetValue();
	if (!RetVal)
		return;

	const FunctionDecl* FD = nullptr;
	if (auto ADC = C.getCurrentAnalysisDeclContext()) {
		FD = dyn_cast<FunctionDecl>(ADC->getDecl());
	}
	if (!FD)
		return;

	auto FuncRetTypeName = FD->getReturnType().getAsString();
	if (FuncRetTypeName == "errno_t")
		return;

	if (!FD->getReturnType()->isIntegerType())
		return;

	if (!isErrnoVar(RetVal, C))
		return;

	auto ls = anzulocalization::LocaleSetting::getInstance();
	uint64_t lang = GetOutputLocaleSetting(C.getAnalysisManager().getAnalyzerOptions(), ls->getSupportedLangMask());
	std::string fmt = ls->parseMsgs(anzulocalization::ErrnoReturnTypeChecker, lang);
	std::string fd = FD->getNameAsString();
	std::string Msg = std::vformat(fmt, std::make_format_args(fd));

	reportBug(FD, Msg, RetVal->getBeginLoc(), C.getBugReporter());
}

bool ErrnoReturnTypeChecker::isErrnoVar(const Expr* E, CheckerContext& C) const {
	E = E->IgnoreParenCasts();
	if (E->getBeginLoc().isMacroID()) {
		auto Name = getSourceCode(C.getASTContext(), E->getBeginLoc(), E->getEndLoc());
		return ErrnoNames.find(Name) != ErrnoNames.end();
	}

	if (auto DRE = dyn_cast<DeclRefExpr>(E)) {
		if (auto D = DRE->getDecl()) {
			if (auto VD = dyn_cast<VarDecl>(D)) {
				if (VD->getNameAsString() == "errno") {
					auto FilePath = C.getSourceManager().getFilename(VD->getLocation());
					auto FileName = llvm::sys::path::filename(FilePath);
					return FileName == "errno.h";
				}
			}
		}
	}

	return false;
}

void ErrnoReturnTypeChecker::reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
	if (Loc.isMacroID())
		return;
	
	if (!BT) {
		BT.reset(new BuiltinBug(
			this, "ErrnoReturnTypeChecker"));
	}

	// Report the issue        
	PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
	auto Report = std::make_unique<BasicBugReport>(
		*BT, Msg, createRuleExtData(1, "ErrnoReturnTypeChecker"), DLoc);
	Report->setDeclWithIssue(FD);
	BR.emitReport(std::move(Report));
}

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerErrnoReturnTypeChecker(CheckerManager& Mgr) {
	Mgr.registerChecker<ErrnoReturnTypeChecker>();
}

bool ento::shouldRegisterErrnoReturnTypeChecker(const CheckerManager& mgr) {
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
	registry.addChecker<ErrnoReturnTypeChecker>("anzu.ErrnoReturnTypeChecker", "Only use typedef on non-pointer types", "");
}

#endif