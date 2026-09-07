#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/AST/EvaluatedExprVisitor.h"
#include "../Utils.h"

using namespace clang;
using namespace clang::ento;

namespace {
    class UninitializedFieldVisitor
        : public EvaluatedExprVisitor<UninitializedFieldVisitor> {
        ASTContext& AST;
        // List of Decls to generate a warning on.  Also remove Decls that become
        // initialized.
        llvm::SmallPtrSetImpl<ValueDecl*>& Decls;
        // List of base classes of the record.  Classes are removed after their
        // initializers.
        llvm::SmallPtrSetImpl<QualType>& BaseClasses;
        // Vector of decls to be removed from the Decl set prior to visiting the
        // nodes.  These Decls may have been initialized in the prior initializer.
        llvm::SmallVector<ValueDecl*, 4> DeclsToRemove;
        // If non-null, add a note to the warning pointing back to the constructor.
        const CXXConstructorDecl* Constructor;
        // Variables to hold state when processing an initializer list.  When
        // InitList is true, special case initialization of FieldDecls matching
        // InitListFieldDecl.
        bool InitList;
        FieldDecl* InitListFieldDecl;
        llvm::SmallVector<unsigned, 4> InitFieldIndex;

        std::list<const Expr*> ExceptInitExprs;
    public:
        const std::list<const Expr*> GetExprs() const {
            return ExceptInitExprs;
        }
    public:
        typedef EvaluatedExprVisitor<UninitializedFieldVisitor> Inherited;
        UninitializedFieldVisitor(ASTContext& AST,
            llvm::SmallPtrSetImpl<ValueDecl*>& Decls,
            llvm::SmallPtrSetImpl<QualType>& BaseClasses)
            : Inherited(AST), AST(AST), Decls(Decls), BaseClasses(BaseClasses),
            Constructor(nullptr), InitList(false), InitListFieldDecl(nullptr) {}

        // Returns true if the use of ME is not an uninitialized use.
        bool IsInitListMemberExprInitialized(MemberExpr* ME,
            bool CheckReferenceOnly) {
            llvm::SmallVector<FieldDecl*, 4> Fields;
            bool ReferenceField = false;
            while (ME) {
                FieldDecl* FD = dyn_cast<FieldDecl>(ME->getMemberDecl());
                if (!FD)
                    return false;
                Fields.push_back(FD);
                if (FD->getType()->isReferenceType())
                    ReferenceField = true;
                ME = dyn_cast<MemberExpr>(ME->getBase()->IgnoreParenImpCasts());
            }

            // Binding a reference to an uninitialized field is not an
            // uninitialized use.
            if (CheckReferenceOnly && !ReferenceField)
                return true;

            llvm::SmallVector<unsigned, 4> UsedFieldIndex;
            // Discard the first field since it is the field decl that is being
            // initialized.
            for (const FieldDecl* FD : llvm::drop_begin(llvm::reverse(Fields)))
                UsedFieldIndex.push_back(FD->getFieldIndex());

            for (auto UsedIter = UsedFieldIndex.begin(),
                UsedEnd = UsedFieldIndex.end(),
                OrigIter = InitFieldIndex.begin(),
                OrigEnd = InitFieldIndex.end();
                UsedIter != UsedEnd && OrigIter != OrigEnd; ++UsedIter, ++OrigIter) {
                if (*UsedIter < *OrigIter)
                    return true;
                if (*UsedIter > *OrigIter)
                    break;
            }

            return false;
        }

        void HandleMemberExpr(MemberExpr* ME, bool CheckReferenceOnly,
            bool AddressOf) {
            if (isa<EnumConstantDecl>(ME->getMemberDecl()))
                return;

            // FieldME is the inner-most MemberExpr that is not an anonymous struct
            // or union.
            MemberExpr* FieldME = ME;

            bool AllPODFields = FieldME->getType().isPODType(AST);

            Expr* Base = ME;
            while (MemberExpr* SubME =
                dyn_cast<MemberExpr>(Base->IgnoreParenImpCasts())) {

                if (isa<VarDecl>(SubME->getMemberDecl()))
                    return;

                if (FieldDecl* FD = dyn_cast<FieldDecl>(SubME->getMemberDecl()))
                    if (!FD->isAnonymousStructOrUnion())
                        FieldME = SubME;

                if (!FieldME->getType().isPODType(AST))
                    AllPODFields = false;

                Base = SubME->getBase();
            }

            if (!isa<CXXThisExpr>(Base->IgnoreParenImpCasts())) {
                Visit(Base);
                return;
            }

            if (AddressOf && AllPODFields)
                return;

            ValueDecl* FoundVD = FieldME->getMemberDecl();

            if (ImplicitCastExpr* BaseCast = dyn_cast<ImplicitCastExpr>(Base)) {
                while (isa<ImplicitCastExpr>(BaseCast->getSubExpr())) {
                    BaseCast = cast<ImplicitCastExpr>(BaseCast->getSubExpr());
                }

                if (BaseCast->getCastKind() == CK_UncheckedDerivedToBase) {
                    QualType T = BaseCast->getType();
                    if (T->isPointerType() &&
                        BaseClasses.count(T->getPointeeType())) {
                        //S.Diag(FieldME->getExprLoc(), diag::warn_base_class_is_uninit)
                        //    << T->getPointeeType() << FoundVD;
                    }
                }
            }

            if (!Decls.count(FoundVD))
                return;

            const bool IsReference = FoundVD->getType()->isReferenceType();

            if (InitList && !AddressOf && FoundVD == InitListFieldDecl) {
                // Special checking for initializer lists.
                if (IsInitListMemberExprInitialized(ME, CheckReferenceOnly)) {
                    return;
                }
            }
            else {
                // Prevent double warnings on use of unbounded references.
                if (CheckReferenceOnly && !IsReference)
                    return;
            }

            ExceptInitExprs.push_back(FieldME);
        }

        void HandleValue(Expr* E, bool AddressOf) {
            E = E->IgnoreParens();

            if (MemberExpr* ME = dyn_cast<MemberExpr>(E)) {
                HandleMemberExpr(ME, false /*CheckReferenceOnly*/,
                    AddressOf /*AddressOf*/);
                return;
            }

            if (ConditionalOperator* CO = dyn_cast<ConditionalOperator>(E)) {
                Visit(CO->getCond());
                HandleValue(CO->getTrueExpr(), AddressOf);
                HandleValue(CO->getFalseExpr(), AddressOf);
                return;
            }

            if (BinaryConditionalOperator* BCO =
                dyn_cast<BinaryConditionalOperator>(E)) {
                Visit(BCO->getCond());
                HandleValue(BCO->getFalseExpr(), AddressOf);
                return;
            }

            if (OpaqueValueExpr* OVE = dyn_cast<OpaqueValueExpr>(E)) {
                HandleValue(OVE->getSourceExpr(), AddressOf);
                return;
            }

            if (BinaryOperator* BO = dyn_cast<BinaryOperator>(E)) {
                switch (BO->getOpcode()) {
                default:
                    break;
                case(BO_PtrMemD):
                case(BO_PtrMemI):
                    HandleValue(BO->getLHS(), AddressOf);
                    Visit(BO->getRHS());
                    return;
                case(BO_Comma):
                    Visit(BO->getLHS());
                    HandleValue(BO->getRHS(), AddressOf);
                    return;
                }
            }

            Visit(E);
        }

        void CheckInitListExpr(InitListExpr* ILE) {
            InitFieldIndex.push_back(0);
            for (auto* Child : ILE->children()) {
                if (InitListExpr* SubList = dyn_cast<InitListExpr>(Child)) {
                    CheckInitListExpr(SubList);
                }
                else {
                    Visit(Child);
                }
                ++InitFieldIndex.back();
            }
            InitFieldIndex.pop_back();
        }

        void CheckInitializer(Expr* E, const CXXConstructorDecl* FieldConstructor,
            FieldDecl* Field, const Type* BaseClass) {
            // Remove Decls that may have been initialized in the previous
            // initializer.
            for (ValueDecl* VD : DeclsToRemove)
                Decls.erase(VD);
            DeclsToRemove.clear();

            Constructor = FieldConstructor;
            InitListExpr* ILE = dyn_cast<InitListExpr>(E);

            if (ILE && Field) {
                InitList = true;
                InitListFieldDecl = Field;
                InitFieldIndex.clear();
                CheckInitListExpr(ILE);
            }
            else {
                InitList = false;
                Visit(E);
            }

            if (Field)
                Decls.erase(Field);
            if (BaseClass)
                BaseClasses.erase(BaseClass->getCanonicalTypeInternal());
        }

        void VisitMemberExpr(MemberExpr* ME) {
            // All uses of unbounded reference fields will warn.
            HandleMemberExpr(ME, true /*CheckReferenceOnly*/, false /*AddressOf*/);
        }

        void VisitImplicitCastExpr(ImplicitCastExpr* E) {
            if (E->getCastKind() == CK_LValueToRValue) {
                HandleValue(E->getSubExpr(), false /*AddressOf*/);
                return;
            }

            Inherited::VisitImplicitCastExpr(E);
        }

        void VisitCXXConstructExpr(CXXConstructExpr* E) {
            if (E->getConstructor()->isCopyConstructor()) {
                Expr* ArgExpr = E->getArg(0);
                if (InitListExpr* ILE = dyn_cast<InitListExpr>(ArgExpr))
                    if (ILE->getNumInits() == 1)
                        ArgExpr = ILE->getInit(0);
                if (ImplicitCastExpr* ICE = dyn_cast<ImplicitCastExpr>(ArgExpr))
                    if (ICE->getCastKind() == CK_NoOp)
                        ArgExpr = ICE->getSubExpr();
                HandleValue(ArgExpr, false /*AddressOf*/);
                return;
            }
            Inherited::VisitCXXConstructExpr(E);
        }

        void VisitCXXMemberCallExpr(CXXMemberCallExpr* E) {
            Expr* Callee = E->getCallee();
            if (isa<MemberExpr>(Callee)) {
                HandleValue(Callee, false /*AddressOf*/);
                for (auto* Arg : E->arguments())
                    Visit(Arg);
                return;
            }

            Inherited::VisitCXXMemberCallExpr(E);
        }

        void VisitCallExpr(CallExpr* E) {
            // Treat std::move as a use.
            if (E->isCallToStdMove()) {
                HandleValue(E->getArg(0), /*AddressOf=*/false);
                return;
            }

            Inherited::VisitCallExpr(E);
        }

        void VisitCXXOperatorCallExpr(CXXOperatorCallExpr* E) {
            Expr* Callee = E->getCallee();

            if (isa<UnresolvedLookupExpr>(Callee))
                return Inherited::VisitCXXOperatorCallExpr(E);

            Visit(Callee);
            for (auto* Arg : E->arguments())
                HandleValue(Arg->IgnoreParenImpCasts(), false /*AddressOf*/);
        }

        void VisitBinaryOperator(BinaryOperator* E) {
            // If a field assignment is detected, remove the field from the
            // uninitiailized field set.
            if (E->getOpcode() == BO_Assign)
                if (MemberExpr* ME = dyn_cast<MemberExpr>(E->getLHS()))
                    if (FieldDecl* FD = dyn_cast<FieldDecl>(ME->getMemberDecl()))
                        if (!FD->getType()->isReferenceType())
                            DeclsToRemove.push_back(FD);

            if (E->isCompoundAssignmentOp()) {
                HandleValue(E->getLHS(), false /*AddressOf*/);
                Visit(E->getRHS());
                return;
            }

            Inherited::VisitBinaryOperator(E);
        }

        void VisitUnaryOperator(UnaryOperator* E) {
            if (E->isIncrementDecrementOp()) {
                HandleValue(E->getSubExpr(), false /*AddressOf*/);
                return;
            }
            if (E->getOpcode() == UO_AddrOf) {
                if (MemberExpr* ME = dyn_cast<MemberExpr>(E->getSubExpr())) {
                    HandleValue(ME->getBase(), true /*AddressOf*/);
                    return;
                }
            }

            Inherited::VisitUnaryOperator(E);
        }
    };

    class MemberInitializedListChecker : public Checker<check::ASTDecl<CXXConstructorDecl>> {
        mutable std::unique_ptr<BugType> BT;

    public:
        MemberInitializedListChecker() {}

        void checkASTDecl(const CXXConstructorDecl* CD, AnalysisManager& Mgr, BugReporter& BR) const {
            if (CD->isInvalidDecl())
                return;

            const CXXRecordDecl* RD = CD->getParent();

            if (RD->isDependentContext())
                return;

            if (!RD->hasDefinition())
                return;

            // Holds fields that are uninitialized.
            llvm::SmallPtrSet<ValueDecl*, 4> UninitializedFields;

            // At the beginning, all fields are uninitialized.
            for (auto* I : RD->decls()) {
                if (auto* FD = dyn_cast<FieldDecl>(I)) {
                    UninitializedFields.insert(FD);
                }
                else if (auto* IFD = dyn_cast<IndirectFieldDecl>(I)) {
                    UninitializedFields.insert(IFD->getAnonField());
                }
            }

            llvm::SmallPtrSet<QualType, 4> UninitializedBaseClasses;
            for (auto I : RD->bases())
                UninitializedBaseClasses.insert(I.getType().getCanonicalType());

            if (UninitializedFields.empty() && UninitializedBaseClasses.empty())
                return;

            UninitializedFieldVisitor UninitializedChecker(Mgr.getASTContext(), UninitializedFields,
                UninitializedBaseClasses);

            for (const auto* FieldInit : CD->inits()) {
                if (UninitializedFields.empty() && UninitializedBaseClasses.empty())
                    break;

                Expr* InitExpr = FieldInit->getInit();
                if (!InitExpr)
                    continue;

                auto a = ToString(InitExpr);
                if (CXXDefaultInitExpr* Default =
                    dyn_cast<CXXDefaultInitExpr>(InitExpr)) {
                    InitExpr = Default->getExpr();
                    if (!InitExpr)
                        continue;
                    // In class initializers will point to the constructor.
                    UninitializedChecker.CheckInitializer(InitExpr, CD,
                        FieldInit->getAnyMember(),
                        FieldInit->getBaseClass());
                }
                else {
                    UninitializedChecker.CheckInitializer(InitExpr, nullptr,
                        FieldInit->getAnyMember(),
                        FieldInit->getBaseClass());
                }
            }
            auto ls = anzulocalization::LocaleSetting::getInstance();
            uint64_t lang = GetOutputLocaleSetting(BR.getAnalyzerOptions(), ls->getSupportedLangMask());
            std::string Msg = ls->parseMsgs(anzulocalization::MemberInitializedListChecker, lang);
            auto& Exprs = UninitializedChecker.GetExprs();
            for (auto& E : Exprs) {
                reportBug(CD, Msg, E->getExprLoc(), BR);
            }
        }

        void reportBug(const Decl* FD, const std::string& Msg, const SourceLocation& Loc, BugReporter& BR) const {
			if (Loc.isMacroID())
				return;
			
            if (!BT)
                BT = std::make_unique<BuiltinBug>(this, "MemberInitializedListChecker");

            // Report the issue        
            PathDiagnosticLocation DLoc(Loc, BR.getSourceManager());
            auto Report = std::make_unique<BasicBugReport>(
                *BT, Msg, createRuleExtData(1, "MemberInitializedListChecker"), DLoc);
            Report->setDeclWithIssue(FD);
            BR.emitReport(std::move(Report));
        }

    };
} // namespace

/// Checker registration
#if RELEASE_BUNDLE
void ento::registerMemberInitializedListChecker(CheckerManager& Mgr) {
    Mgr.registerChecker<MemberInitializedListChecker>();
}

bool ento::shouldRegisterMemberInitializedListChecker(const CheckerManager& mgr) {
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
    registry.addChecker<MemberInitializedListChecker>("anzu.MemberInitializedListChecker", "The order of the initialization list is incorrect", "");
}

#endif