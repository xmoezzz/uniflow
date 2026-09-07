#pragma once

#include "clang/StaticAnalyzer/Core/BugReporter/BugReporter.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ProgramStateTrait.h"

#include "json.hpp"
#include <string>
#include <vector>

struct AnzuCallItem {
    std::string FileName;
    std::string Function;
    int32_t StartLineNo, StartLineCursor;
    int32_t EndLineNo, EndLineCursor;

    AnzuCallItem() {
        StartLineNo = -1;
        StartLineCursor = -1;
        EndLineNo = -1;
        EndLineCursor = -1;
    }

    AnzuCallItem(const AnzuCallItem& Item) {
        FileName = Item.FileName;
        Function = Item.Function;
        StartLineNo = Item.StartLineNo;
        StartLineCursor = Item.StartLineCursor;
        EndLineNo = Item.EndLineNo;
        EndLineCursor = Item.EndLineCursor;
    }

    AnzuCallItem(AnzuCallItem&& Item) {
        FileName = std::move(Item.FileName);
        Function = std::move(Item.Function);
        StartLineNo = Item.StartLineNo;
        StartLineCursor = Item.StartLineCursor;
        EndLineNo = Item.EndLineNo;
        EndLineCursor = Item.EndLineCursor;
    }
    
    AnzuCallItem& operator=(const AnzuCallItem& Item) {
        FileName = Item.FileName;
        Function = Item.Function;
        StartLineNo = Item.StartLineNo;
        StartLineCursor = Item.StartLineCursor;
        EndLineNo = Item.EndLineNo;
        EndLineCursor = Item.EndLineCursor;

        return *this;
    }
};

struct AnzuBugInfo {
    std::string BugID;
    std::string BugDesc;
    std::string FileName;
    int32_t StartLineNo, StartLineCursor;
    int32_t EndLineNo, EndLineCursor;

    std::vector<AnzuCallItem> CallChain;

    AnzuBugInfo() {
        StartLineNo = -1;
        StartLineCursor = -1;
        EndLineNo = -1;
        EndLineCursor = -1;
    }

    AnzuBugInfo(const AnzuBugInfo& Info) {
        BugID = Info.BugID;
        BugDesc = Info.BugDesc;
        FileName = Info.FileName;
        StartLineNo = Info.StartLineNo;
        StartLineCursor = Info.StartLineCursor;
        EndLineNo = Info.EndLineNo;
        EndLineCursor = Info.EndLineCursor;
    }

    AnzuBugInfo(AnzuBugInfo&& Info) {
        BugID = std::move(Info.BugID);
        BugDesc = std::move(Info.BugDesc);
        FileName = std::move(Info.FileName);
        StartLineNo = Info.StartLineNo;
        StartLineCursor = Info.StartLineCursor;
        EndLineNo = Info.EndLineNo;
        EndLineCursor = Info.EndLineCursor;
    }

    AnzuBugInfo& operator=(const AnzuBugInfo& Info) {
        BugID = Info.BugID;
        BugDesc = Info.BugDesc;
        FileName = Info.FileName;
        StartLineNo = Info.StartLineNo;
        StartLineCursor = Info.StartLineCursor;
        EndLineNo = Info.EndLineNo;
        EndLineCursor = Info.EndLineCursor;

        return *this;
    }
};

inline std::string AnzuBugInfoToJson(AnzuBugInfo& Info) {
    nlohmann::json Json;
    Json["BugID"] = Info.BugID;
    Json["BugDesc"] = Info.BugDesc;
    Json["FileName"] = Info.FileName;
    Json["StartLineNo"] = Info.StartLineNo;
    Json["StartLineCursor"] = Info.StartLineCursor;
    Json["EndLineNo"] = Info.EndLineNo;
    Json["EndLineCursor"] = Info.EndLineCursor;

    nlohmann::json CallChain;
    for (auto& Item : Info.CallChain) {
        nlohmann::json CallItem;
        CallItem["FileName"] = Item.FileName;
        CallItem["Function"] = Item.Function;
        CallItem["StartLineNo"] = Item.StartLineNo;
        CallItem["StartLineCursor"] = Item.StartLineCursor;
        CallItem["EndLineNo"] = Item.EndLineNo;
        CallItem["EndLineCursor"] = Item.EndLineCursor;
        CallChain.push_back(CallItem);
    }
    Json["CallChain"] = CallChain;

    return Json.dump();
}


namespace clang {
namespace ento {

std::optional<AnzuCallItem> callFrameFromStackFrame(const StackFrameContext *CurrentFrame, CheckerContext &C);
std::vector<AnzuCallItem> getCallChain(CheckerContext &C);
AnzuBugInfo generateBug(
    const std::string& BugId, 
    const std::string& BugDesc, 
    CheckerContext &C,
    const ExplodedNode *Node, 
    bool WalkCallChain = false
);

};
};
