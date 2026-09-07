def Scs : Package<"scs">;
def Anzu : Package<"anzu">;

let ParentPackage = Scs in {

def AnzuTaintChecker : Checker<"taint">,
  HelpText<"taint data analyze">,
  CheckerOptions<[
    CmdLineOption<String,
                  "Config",
                  "taint rules dir.",
                  "\"\"",
                  Released>
  ]>,
  Documentation<NotDocumented>;

} // end "scs"

let ParentPackage = Anzu in {

def AssignmentInLogicalOpChecker : Checker<"AssignmentInLogicalOpChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def AssignmentSafetyChecker : Checker<"AssignmentSafetyChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def AvoidParamNameInProtoChecker : Checker<"AvoidParamNameInProtoChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def HardcodedCryptoKeyChecker : Checker<"HardcodedCryptoKeyChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def RandUsageChecker : Checker<"RandUsageChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def WeakCryptoChecker : Checker<"WeakCryptoChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def ASCIIChecker : Checker<"ASCIIChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def AbsolutePathChecker : Checker<"AbsolutePathChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def AlignedAllocReallocChecker : Checker<"AlignedAllocReallocChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def AllocationDeallocationChecker : Checker<"AllocationDeallocationChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def ArgumentCountChecker : Checker<"ArgumentCountChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def ArgumentTypeChecker : Checker<"ArgumentTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def ArgumentValidationChecker : Checker<"ArgumentValidationChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def ArrayBoundChecker2 : Checker<"ArrayBoundChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def ArrayIndexChecker2 : Checker<"ArrayIndexChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def AssertChecker : Checker<"AssertChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def FunctionNameAsIdentifierChecker : Checker<"FunctionNameAsIdentifierChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def LabelNameChecker : Checker<"LabelNameChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def MultiLabelChecker : Checker<"MultiLabelChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def ParameterTypeChecker : Checker<"ParameterTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def CharSignChecker : Checker<"CharSignChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def TypedefRedefinitionChecker : Checker<"TypedefRedefinitionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def CompleteStructDeclarationChecker : Checker<"CompleteStructDeclarationChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def AvoidProceduresAsParametersChecker : Checker<"AvoidProceduresAsParametersChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LimitFunctionParametersChecker : Checker<"LimitFunctionParametersChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CheckMainSignatureChecker : Checker<"CheckMainSignatureChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FunctionLengthChecker : Checker<"FunctionLengthChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CheckEmptyBranchChecker : Checker<"CheckEmptyBranchChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CheckEmptyElseBranchChecker : Checker<"CheckEmptyElseBranchChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SwitchDefaultChecker : Checker<"SwitchDefaultChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CheckCaseBreakChecker : Checker<"CheckCaseBreakChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CheckCaseEmptyChecker : Checker<"CheckCaseEmptyChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FunctionPointerChecker : Checker<"FunctionPointerChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PointerComparisonChecker : Checker<"PointerComparisonChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PointerArithmeticChecker : Checker<"PointerArithmeticChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SignedShiftChecker : Checker<"SignedShiftChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ShiftOverflowChecker : Checker<"ShiftOverflowChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnsignedTypeAssignNegativeChecker : Checker<"UnsignedTypeAssignNegativeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BitFieldSizeChecker : Checker<"BitFieldSizeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BitSizeTypeChecker : Checker<"BitSizeTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def AssignTypeChecker : Checker<"AssignTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LogicalNotOnConstantChecker : Checker<"LogicalNotOnConstantChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def EnumUsageChecker : Checker<"EnumUsageChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def OverflowChecker : Checker<"OverflowChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BitwiseOnBoolChecker : Checker<"BitwiseOnBoolChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BitwiseOnBooleanChecker : Checker<"BitwiseOnBooleanChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MixedTypeOperationChecker : Checker<"MixedTypeOperationChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MainFileNotUseFuncChecker : Checker<"MainFileNotUseFuncChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnusedStaticFunctionChecker : Checker<"UnusedStaticFunctionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MultipleRelatedFunctionCallsChecker : Checker<"MultipleRelatedFunctionCallsChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnusedParameterChecker : Checker<"UnusedParameterChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ReturnTypeChecker : Checker<"ReturnTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FloatingPointLoopVariableChecker : Checker<"FloatingPointLoopVariableChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LocalLoopVariableChecker : Checker<"LocalLoopVariableChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ForcedPointerCastChecker : Checker<"ForcedPointerCastChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def IntAssignmentPointerChecker : Checker<"IntAssignmentPointerChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnnecessaryCastChecker : Checker<"UnnecessaryCastChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def EnumInitializationChecker2 : Checker<"EnumInitializationChecker2">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UseUninitializedVariableChecker : Checker<"UseUninitializedVariableChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FloatEqualityComparisonChecker : Checker<"FloatEqualityComparisonChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LogicalExpressionChecker : Checker<"LogicalExpressionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SwitchLogicalExpressionChecker : Checker<"SwitchLogicalExpressionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ExplicitLogicalExpressionChecker : Checker<"ExplicitLogicalExpressionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def EnumNameChecker : Checker<"EnumNameChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def VariableShadowingChecker : Checker<"VariableShadowingChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ParameterShadowingChecker : Checker<"ParameterShadowingChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def RedefinitionInInnerBlockChecker : Checker<"RedefinitionInInnerBlockChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MacroParamParenChecker : Checker<"MacroParamParenChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LogicalExprParenChecker : Checker<"LogicalExprParenChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FunctionVarArgsTypeCheckerChecker : Checker<"FunctionVarArgsTypeCheckerChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def KeywordRefinedChecker : Checker<"KeywordRefinedChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MacroBodyParenChecker : Checker<"MacroBodyParenChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MacroBodyKeywordsChecker : Checker<"MacroBodyKeywordsChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def WhileBodyParenChecker : Checker<"WhileBodyParenChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BranchBodyParenChecker : Checker<"BranchBodyParenChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def IfElseIfElseChecker : Checker<"IfElseIfElseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def EmptySwitchChecker : Checker<"EmptySwitchChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SwitchOnlyDefaultChecker : Checker<"SwitchOnlyDefaultChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DisableGotoChecker : Checker<"DisableGotoChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def AssignmentInConditionChecker : Checker<"AssignmentInConditionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CommaExprChecker : Checker<"CommaExprChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ConfusingNamingO01lChecker : Checker<"ConfusingNamingO01lChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def AddOrSubAssignChecker : Checker<"AddOrSubAssignChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def IncDecUseChecker : Checker<"IncDecUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ContinueUseChecker : Checker<"ContinueUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ConditionExprUseChecker : Checker<"ConditionExprUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def NullStmtUseChecker : Checker<"NullStmtUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ReturnUseChecker : Checker<"ReturnUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BreakUseChecker : Checker<"BreakUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def InfinityLoopChecker : Checker<"InfinityLoopChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LoopCondConstantChecker : Checker<"LoopCondConstantChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MacroBodyHashChecker : Checker<"MacroBodyHashChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MacroBodyMultHashChecker : Checker<"MacroBodyMultHashChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MacroRedefinedTypesChecker : Checker<"MacroRedefinedTypesChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PragmaUseChecker : Checker<"PragmaUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def IncludeFilePathChecker : Checker<"IncludeFilePathChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def IncludeFileAbsPathChecker : Checker<"IncludeFileAbsPathChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def RegisterUseChecker : Checker<"RegisterUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MultPointerTypeDefChecker : Checker<"MultPointerTypeDefChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def RedefinedMacroChecker : Checker<"RedefinedMacroChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CharTypeOperatorChecker : Checker<"CharTypeOperatorChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FunctionPointerExplicitChecker : Checker<"FunctionPointerExplicitChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ParameterAssignmentChecker : Checker<"ParameterAssignmentChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SignedBitFieldWidthChecker : Checker<"SignedBitFieldWidthChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def RefUndefOrAlreadyFreePinterChecker : Checker<"RefUndefOrAlreadyFreePinterChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PointerInitializationChecker : Checker<"PointerInitializationChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DynamicAllocPointerUseChecker : Checker<"DynamicAllocPointerUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FilePointerLeakChecker : Checker<"FilePointerLeakChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def EmptyBranchChecker : Checker<"EmptyBranchChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BoolSwitchChecker : Checker<"BoolSwitchChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def GotoChecker : Checker<"GotoChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FloatAssignToIntChecker : Checker<"FloatAssignToIntChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def IntegerOverflowChecker : Checker<"IntegerOverflowChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LogicalBitwiseOperationChecker : Checker<"LogicalBitwiseOperationChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def NegativeShiftChecker : Checker<"NegativeShiftChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ConstValueNotLogicOpChecker : Checker<"ConstValueNotLogicOpChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def EnumValueChecker : Checker<"EnumValueChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def RefAlreadyFreePinterChecker : Checker<"RefAlreadyFreePinterChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MallocFreeChecker : Checker<"MallocFreeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def OverrideStdLibFunctionChecker : Checker<"OverrideStdLibFunctionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnusedReturnValueChecker : Checker<"UnusedReturnValueChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def RedundantVoidCastChecker : Checker<"RedundantVoidCastChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def WhileCtrlVarDeclChecker : Checker<"WhileCtrlVarDeclChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def IntegerAssignIntegerChecker : Checker<"IntegerAssignIntegerChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DoubleAssignFloatChecker : Checker<"DoubleAssignFloatChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def NoOpConversionChecker : Checker<"NoOpConversionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LogicalComparisonChecker : Checker<"LogicalComparisonChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnsignedComparisonChecker : Checker<"UnsignedComparisonChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnsignedSignedComparisonChecker : Checker<"UnsignedSignedComparisonChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def TypedefNameChecker : Checker<"TypedefNameChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CaseSensitiveChecker : Checker<"CaseSensitiveChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ConfusingNamingChecker : Checker<"ConfusingNamingChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def NullAsIntChecker : Checker<"NullAsIntChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def KeywordRefinedKeywordChecker : Checker<"KeywordRefinedKeywordChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def TypedefKeywordChecker : Checker<"TypedefKeywordChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def AnonymousNameStructChecker : Checker<"AnonymousNameStructChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FunctionArgNameExistChecker : Checker<"FunctionArgNameExistChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ExternVarInFunctionBodyChecker : Checker<"ExternVarInFunctionBodyChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ArrayVarBoundDefinedChecker : Checker<"ArrayVarBoundDefinedChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ExternVarHasInitChecker : Checker<"ExternVarHasInitChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FunctionVoidParamTypeChecker : Checker<"FunctionVoidParamTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ConditionExprParenChecker : Checker<"ConditionExprParenChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def NumZeroCastPointerChecker : Checker<"NumZeroCastPointerChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def AssignInSizeofChecker : Checker<"AssignInSizeofChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DisableForInfinityLoopChecker : Checker<"DisableForInfinityLoopChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PointerAssignmentPointerChecker : Checker<"PointerAssignmentPointerChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnPointerAndPointerAssignChecker : Checker<"UnPointerAndPointerAssignChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DisableForBodyModifyCtrlVarChecker : Checker<"DisableForBodyModifyCtrlVarChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PointerMustBeNullAfterFreeChecker : Checker<"PointerMustBeNullAfterFreeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CharArrayInitChecker : Checker<"CharArrayInitChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ValueDependSequencePointChecker : Checker<"ValueDependSequencePointChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FloatingPointComparisonChecker : Checker<"FloatingPointComparisonChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def IntegerAssignIntegerExChecker : Checker<"IntegerAssignIntegerExChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BoolArithChecker : Checker<"BoolArithChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BitTypeWithCondChecker : Checker<"BitTypeWithCondChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PointerAlignChecker : Checker<"PointerAlignChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def VirtualOverrideConstFunction : Checker<"VirtualOverrideConstFunction">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BSTRUsageChecker : Checker<"BSTRUsageChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SuspiciousSemicolonChecker : Checker<"SuspiciousSemicolonChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def StrongTypedefArgumentMismatchChecker : Checker<"StrongTypedefArgumentMismatchChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def StrongTypedefReturnMismatchChecker : Checker<"StrongTypedefReturnMismatchChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def StrongTypedefMismatchChecker : Checker<"StrongTypedefMismatchChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LongLongTypeChecker : Checker<"LongLongTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MemberInitializedListChecker : Checker<"MemberInitializedListChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MisusedFunctionAddressChecker : Checker<"MisusedFunctionAddressChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnusedLabelChecker : Checker<"UnusedLabelChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PointerTypeCastChecker : Checker<"PointerTypeCastChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BitFieldPointerUseChecker : Checker<"BitFieldPointerUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BuildinLimitMacroUseChecker : Checker<"BuildinLimitMacroUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UninitializedPointerChecker : Checker<"UninitializedPointerChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def EOFComparisonChecker : Checker<"EOFComparisonChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SignedIntegerOverflowChecker : Checker<"SignedIntegerOverflowChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnsignedIntegerOverflowChecker : Checker<"UnsignedIntegerOverflowChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SensitiveDataPlacementChecker : Checker<"SensitiveDataPlacementChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PointerArithmeticExChecker : Checker<"PointerArithmeticExChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ConfusingNamesChecker : Checker<"ConfusingNamesChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def StaticAssertUseChecker : Checker<"StaticAssertUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SingleDeclarationChecker : Checker<"SingleDeclarationChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def OnlyNonPointerTypeTypedefChecker : Checker<"OnlyNonPointerTypeTypedefChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ErrnoReturnTypeChecker : Checker<"ErrnoReturnTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LongNumStringlLChecker : Checker<"LongNumStringlLChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SwitchDeclInFirstCasePreChecker : Checker<"SwitchDeclInFirstCasePreChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ErrnoResultChecker : Checker<"ErrnoResultChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BitOpExprParenChecker : Checker<"BitOpExprParenChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ConstVarWriteOpChecker : Checker<"ConstVarWriteOpChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UseSizeofCalLengthChecker : Checker<"UseSizeofCalLengthChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LogicalAndRelComparisonChecker : Checker<"LogicalAndRelComparisonChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ShiftOnCharOrShortChecker : Checker<"ShiftOnCharOrShortChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def NotMatchTypePointerAccessChecker : Checker<"NotMatchTypePointerAccessChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SizeofChecker : Checker<"SizeofChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FileHandleCopyChecker : Checker<"FileHandleCopyChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FSetposArgChecker : Checker<"FSetposArgChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;

def IntAssignFloatTypeChecker : Checker<"IntAssignFloatTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def IntAssignCharTypeChecker : Checker<"IntAssignCharTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def EnumElementRepValueChecker : Checker<"EnumElementRepValueChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ShortAssignLongTypeChecker : Checker<"ShortAssignLongTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PointerCastIntegerChecker : Checker<"PointerCastIntegerChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnsecurityFunctionChecker : Checker<"UnsecurityFunctionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MutexTypeChecker : Checker<"MutexTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ReadlinkChecker : Checker<"ReadlinkChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def VforkExChecker : Checker<"VforkExChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PutEnvChecker : Checker<"PutEnvChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MacroBodyMultStmtChecker : Checker<"MacroBodyMultStmtChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MacroBodySemiEndChecker : Checker<"MacroBodySemiEndChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ConstStrAssignChecker : Checker<"ConstStrAssignChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CharCondChecker : Checker<"CharCondChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ConstStrJoinChecker : Checker<"ConstStrJoinChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CharArraySizeInitChecker : Checker<"CharArraySizeInitChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CharCastIntChecker : Checker<"CharCastIntChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def VarArraySizeChecker : Checker<"VarArraySizeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ComplexTypeChecker : Checker<"ComplexTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PostfixOpChecker : Checker<"PostfixOpChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ReentryChecker : Checker<"ReentryChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def NoReturnWithReturnChecker : Checker<"NoReturnWithReturnChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DestructorNoexceptChecker : Checker<"DestructorNoexceptChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ThrowChecker : Checker<"ThrowChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ConstructorDestructorTryCatchChecker : Checker<"ConstructorDestructorTryCatchChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CatchOrderChecker : Checker<"CatchOrderChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CStyleCastChecker : Checker<"CStyleCastChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def AvoidReinterpretCastWithMultipleInheritanceChecker : Checker<"AvoidReinterpretCastWithMultipleInheritanceChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CastPreferenceChecker : Checker<"CastPreferenceChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PreferPrefixOperatorChecker : Checker<"PreferPrefixOperatorChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DeleteArrayChecker : Checker<"DeleteArrayChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CvQualificationChecker : Checker<"CvQualificationChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def VariadicChecker : Checker<"VariadicChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DisableCallCStyleStreamChecker : Checker<"DisableCallCStyleStreamChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def EnumRangeChecker : Checker<"EnumRangeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CMemFunctionsInCppChecker : Checker<"CMemFunctionsInCppChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def LoopInequalityChecker : Checker<"LoopInequalityChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PrivateStaticMemberChecker : Checker<"PrivateStaticMemberChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DeprecatedFunctionChecker : Checker<"DeprecatedFunctionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def StdNamespaceChecker : Checker<"StdNamespaceChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SignalHandlerChecker : Checker<"SignalHandlerChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def NullCharTraitsChecker : Checker<"NullCharTraitsChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CopyWithoutResizeChecker : Checker<"CopyWithoutResizeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PrivateMemberChecker : Checker<"PrivateMemberChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CppImplicitConversionChecker : Checker<"CppImplicitConversionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def HidingNonVirtualFuncChecker : Checker<"HidingNonVirtualFuncChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def OverloadAllVirtualFuncChecker : Checker<"OverloadAllVirtualFuncChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DefaultArgInVirtualFuncChecker : Checker<"DefaultArgInVirtualFuncChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DeleteThisChecker : Checker<"DeleteThisChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def RawPointerCopyChecker : Checker<"RawPointerCopyChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MultipleInheritanceChecker : Checker<"MultipleInheritanceChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def NoPrivateDataReturnChecker : Checker<"NoPrivateDataReturnChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SingleParamConstructorChecker : Checker<"SingleParamConstructorChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def VirtualCallChecker2 : Checker<"VirtualCallChecker2">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ObjectSlicingChecker : Checker<"ObjectSlicingChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def VirtualDtorChecker : Checker<"VirtualDtorChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PreferVectorOverArrayChecker : Checker<"PreferVectorOverArrayChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def StdFindUseChecker : Checker<"StdFindUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ExitHandlerChecker : Checker<"ExitHandlerChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SignedIntOddEvenChecker : Checker<"SignedIntOddEvenChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def StringOpFuncReturnUseChecker : Checker<"StringOpFuncReturnUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def TimeOpChecker : Checker<"TimeOpChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MagicNumbersChecker : Checker<"MagicNumbersChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def StructSizeofChecker : Checker<"StructSizeofChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def AssertAndAtexitChecker : Checker<"AssertAndAtexitChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FileOpenChecker : Checker<"FileOpenChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UngetChecker : Checker<"UngetChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def INT05CPPChecker : Checker<"INT05CPPChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MixedBitwiseAndArithmeticChecker : Checker<"MixedBitwiseAndArithmeticChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def MallocResultExplictCastChecker : Checker<"MallocResultExplictCastChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CharTypeChecker : Checker<"CharTypeChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PrintFunctionArgCountChecker : Checker<"PrintFunctionArgCountChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FormatSpecifierTypeMismatchChecker : Checker<"FormatSpecifierTypeMismatchChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FormatStringChecker : Checker<"FormatStringChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PrintfStarChecker : Checker<"PrintfStarChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def PrintfScanfFormatStringChecker : Checker<"PrintfScanfFormatStringChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ScanfWidthLimitChecker : Checker<"ScanfWidthLimitChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def UnicodeMappingChecker : Checker<"UnicodeMappingChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def DisableFunctionChecker : Checker<"DisableFunctionChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def ResourceAllocAndReleaseChecker : Checker<"ResourceAllocAndReleaseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BooleanArithmeticChecker : Checker<"BooleanArithmeticChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def BCryptParamChecker : Checker<"BCryptParamChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def TaintLoopVariableChecker : Checker<"TaintLoopVariableChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def CtypeFuncUseChecker : Checker<"CtypeFuncUseChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def FileStreamReadWriteChecker : Checker<"FileStreamReadWriteChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def RestrictArgChecker : Checker<"RestrictArgChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
def SizeofParamArrayChecker : Checker<"SizeofParamArrayChecker">,
  HelpText<"">,
  Documentation<NotDocumented>;
  
} // end "anzu"


