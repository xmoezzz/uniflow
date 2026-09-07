//===- CheckerHandlerRegistry.h ---------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Static checker preprocessor handler
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_CLANG_FRONTEND_CHECKEHANDLERRREGISTRY_H
#define LLVM_CLANG_FRONTEND_CHECKEHANDLERRREGISTRY_H

#include "clang/Frontend/CompilerInstance.h"
#include "clang/Lex/Preprocessor.h"
#include "llvm/Support/Registry.h"

namespace clang {
namespace checker {
class PreprocessorHandler {
public:
  virtual ~PreprocessorHandler() {}
  virtual void VisitCompilerInstance(CompilerInstance &CI) {}
  virtual void RegistryHandler(Preprocessor &PP) {}
  virtual void PragmaDirective(SourceLocation Loc,
                               PragmaIntroducerKind Introducer) {}
  virtual void InclusionDirective(SourceLocation HashLoc,
                                  const Token &IncludeTok, StringRef FileName,
                                  bool IsAngled, CharSourceRange FilenameRange,
                                  OptionalFileEntryRef File,
                                  StringRef SearchPath, StringRef RelativePath,
                                  const Module *Imported,
                                  SrcMgr::CharacteristicKind FileType) {}
  virtual void MacroDefined(Preprocessor& PP, const Token &MacroNameTok,
                            const MacroDirective *MD) {}
  virtual void MacroUndefined(Preprocessor &PP, const Token &MacroNameTok,
                              const MacroDefinition &MD,
                              const MacroDirective *Undef) {}
};

using PreprocessorHandlerRegistry = llvm::Registry<PreprocessorHandler>;

} // namespace checker
} // namespace clang

#endif // LLVM_CLANG_FRONTEND_CHECKEHANDLERRREGISTRY_H
