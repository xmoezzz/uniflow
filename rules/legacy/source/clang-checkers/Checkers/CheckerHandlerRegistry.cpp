#include "CheckerHandlerRegistry.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/FrontendPluginRegistry.h"

using namespace llvm;
using namespace clang;

namespace {
class PreprocessorCallback : public PPCallbacks {
private:
  const CompilerInstance &CI;

public:
  PreprocessorCallback(const CompilerInstance &CI) : CI(CI) {}

public:
  virtual void PragmaDirective(SourceLocation Loc,
                               PragmaIntroducerKind Introducer) override {

    for (const checker::PreprocessorHandlerRegistry::entry &Item :
         checker::PreprocessorHandlerRegistry::entries()) {
      std::unique_ptr<checker::PreprocessorHandler> Handler =
          Item.instantiate();
      Handler->PragmaDirective(Loc, Introducer);
    }
  }

  virtual void InclusionDirective(
      SourceLocation HashLoc, const Token &IncludeTok, StringRef FileName,
      bool IsAngled, CharSourceRange FilenameRange, OptionalFileEntryRef File,
      StringRef SearchPath, StringRef RelativePath, const Module *Imported,
      SrcMgr::CharacteristicKind FileType) override {
    for (const checker::PreprocessorHandlerRegistry::entry &Item :
         checker::PreprocessorHandlerRegistry::entries()) {
      std::unique_ptr<checker::PreprocessorHandler> Handler =
          Item.instantiate();
      Handler->InclusionDirective(HashLoc, IncludeTok, FileName, IsAngled,
                                  FilenameRange, File, SearchPath, RelativePath,
                                  Imported, FileType);
    }
  }

  virtual void MacroDefined(const Token &MacroNameTok,
                            const MacroDirective *MD) override {
    for (const checker::PreprocessorHandlerRegistry::entry &Item :
         checker::PreprocessorHandlerRegistry::entries()) {
      std::unique_ptr<checker::PreprocessorHandler> Handler =
          Item.instantiate();
      Handler->MacroDefined(CI.getPreprocessor(), MacroNameTok, MD);
    }
  }

  virtual void MacroUndefined(const Token &MacroNameTok,
                              const MacroDefinition &MD,
                              const MacroDirective *Undef) override {
    for (const checker::PreprocessorHandlerRegistry::entry &Item :
         checker::PreprocessorHandlerRegistry::entries()) {
      std::unique_ptr<checker::PreprocessorHandler> Handler =
          Item.instantiate();
      Handler->MacroUndefined(CI.getPreprocessor(), MacroNameTok, MD, Undef);
    }
  }
};

class CheckerASTConsumer : public ASTConsumer {};

class CheckerFrontendAction : public PluginASTAction {
public:
  virtual ActionType getActionType() override { return AddAfterMainAction; }
  std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI,
                                                 StringRef) override {
    HandleDefaultHandler(CI);
    HandleRegistryHandler(CI);
    return std::make_unique<CheckerASTConsumer>();
  }

  bool ParseArgs(const CompilerInstance &CI,
                 const std::vector<std::string> &args) override {
    return true;
  }

private:
  void HandleDefaultHandler(CompilerInstance &CI) {
    auto &PP = CI.getPreprocessor();
    PP.addPPCallbacks(std::make_unique<PreprocessorCallback>(CI));
  }

  void HandleRegistryHandler(CompilerInstance &CI) {
    auto &PP = CI.getPreprocessor();
    for (const checker::PreprocessorHandlerRegistry::entry &Item :
         checker::PreprocessorHandlerRegistry::entries()) {
      std::unique_ptr<checker::PreprocessorHandler> Handler =
          Item.instantiate();
      Handler->RegistryHandler(PP);
    }
  }
};
static FrontendPluginRegistry::Add<CheckerFrontendAction>
    Register("static_checker", "static_checker");
} // namespace

LLVM_INSTANTIATE_REGISTRY(checker::PreprocessorHandlerRegistry)
