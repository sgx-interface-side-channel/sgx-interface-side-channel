#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/Analysis/RegionInfo.h"
#include "llvm/Analysis/RegionIterator.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/BranchProbability.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ValueMapper.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"
#include <set>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <iostream>
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"

using namespace llvm;
static cl::opt<unsigned> MaxLoop(
                                 "max-loop",
                                 cl::desc("Use this max loop for all loops"),cl::Required);
#define DEBUG_TYPE "lt"
/*
 loop部分：
 1.要求使用pass时传入loop的最大次数。
 2.插入一个变量来记录循环。(或分析循环次数)
 3.插入代码在循环不到这样的次数的时候添加冗余指令
*/

namespace {
struct LoopTrans : public ModulePass {
    public:
        static char ID;
          //构造函数
        LoopTrans() : ModulePass(ID) {
            errs() << "Constant iteration Loop Transform Pass: \n";
        }
        std::vector<Loop*> allLoops;
        void getAnalysisUsage(AnalysisUsage &AU) const override {
          AU.addRequired<LoopInfoWrapperPass>();
        }
        static void dfsOnLoops(Loop *L, LoopInfo *loopinfo, std::vector<Loop*> LoopS) {
          std::vector<Loop *> subloops = L->getSubLoops();
          if (!subloops.empty()) {
            // recursive on subloops
            for (auto & subloop : subloops){
                LoopS.push_back(subloop);
                dfsOnLoops(subloop, loopinfo, LoopS);
            }
          }
        }
        bool runOnModule(Module &M) override {
            std::vector<Type *> args;
            args.push_back(Type::getInt32Ty(M.getContext()));
            //声明一个外部函数
            ArrayRef<Type*>  argsRef(args);
            FunctionType *FT = FunctionType::get(Type::getVoidTy(M.getContext()), args, false);
//            AttributeList attr_list = args;

            FunctionCallee myFunc;
            myFunc = M.getOrInsertFunction("max_iter",FT);
//            also can code like this:
//            myFunc = M.getOrInsertFunction("max_iter", return_type,param1_type,param2_type,...,paramx_type);
            Function *monitor = &dyn_cast<Function>(myFunc);
            for (Module::iterator IT = M.begin(), END = M.end(); IT != END; ++IT) {
                if ((*IT).empty()) {
                    continue;
                }else{
                    //find all loops including nested loops
                    LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>(*IT).getLoopInfo();
                    for( auto i = LI.begin(), e=LI.end(); i != e; ++i){
                        Loop *L = *i;
                        allLoops.push_back(L);
                        dfsOnLoops(L, &LI, allLoops);
                    }
                    // deal with all the loops
                    int tmp = 0;
                    for(Loop *lp:allLoops){
                        //也可以这样写
//                        for(Loop::iterator i=lp->begin(),e=lp->end();i!=e;++i){
//                            BasicBlock *bb = dyn_cast<BasicBlock>(*i);
                        //取出loop的头block
                        // TODO: update this variable
                        //For each loop insert a count variable
                        BasicBlock *head_block = lp->getHeader();
                        //loops所在的function的entry_block
                        BasicBlock *entry_block = &head_block->begin()->getFunction()->getEntryBlock();
                        IRBuilder<> Builder_entry(entry_block);
//                        MDNode *node = MDNode::get(M.getContext(), MDString::get(M.getContext(), "loop_"+std::to_string(tmp)));
//                        lp->setLoopID(node);
                        Value* count_int = Builder_entry.CreateAlloca(Type::getInt32Ty(M.getContext()), nullptr,"loop_"+std::to_string(tmp));
//                      ConstantInt *cons_zero = Builder.getInt32(0);
                        Builder_entry.CreateStore(Builder_entry.getInt32(0), count_int);
//                        ArrayRef<Value*> arguments(ConstantInt::get(Type::getInt32Ty(M.getContext()), 5, true));
////                      插入function call
//                        Instruction *newInst = CallInst::Create(monitor, arguments, "");
                        SmallVector<BasicBlock*,8> exiting_blocks;
                        SmallVector<BasicBlock*,8> exit_blocks;
                        lp->getExitingBlocks(exiting_blocks);
                        lp->getExitBlocks(exit_blocks);
                        for (BasicBlock *exit_block:exiting_blocks) {
                            IRBuilder<> Builder_exit(exit_block);
                            Value *tmp_load = Builder_exit.CreateLoad(Type::getInt32Ty(M.getContext()), count_int);
                            Value *tmp_add_by_one = Builder_exit.CreateAdd(tmp_load, Builder_exit.getInt32(1));
                            Builder_exit.CreateStore(tmp_add_by_one, count_int);
                        }
                        for(BasicBlock *exit_block:exit_blocks){
                            //decide to add how many iteraters to it.
                            std::vector<Instruction*> iter_ins;
                            std::vector<BasicBlock*> loop_block = lp->getBlocksVector();
                            for(BasicBlock *bb : loop_block){
                                //Todo: how to add more loops
//                            先运行block combine和branchelimination
                                for (BasicBlock::iterator inst_begin=bb->begin(),inst_end=bb->end(); inst_end!=inst_begin; ++inst_begin) {
                                    auto *inst = dyn_cast<Instruction>(inst_begin);
                                    if (!isa<BranchInst>(inst)&&!isa<CallInst>(inst)&&!isa<ReturnInst>(inst)&&!isa<CmpInst>(inst)) {
                                        Instruction *new_inst = inst->clone();
                                        iter_ins.push_back(new_inst);
                                    }
//                                BasicBlock *entry_block = &inst->getFunction()->getEntryBlock();
//                                errs() << "Inserted the function!\n";
                                }
                            }
                            BasicBlock::iterator end_iter = exit_block->end();
                            end_iter--;
                            end_iter--;
                            BasicBlock* entry = BasicBlock::Create(M.getContext());
                            BasicBlock* new_block = exit_block->splitBasicBlock(end_iter,("split"));
                            entry->insertInto(exit_block->getParent(),new_block);
                            for (Instruction *inst:iter_ins) {
                                inst->insertBefore(dyn_cast<Instruction>(entry->begin()));
                            }
                            tmp++;
                        }
                    }
                }
            }
            /* 1.for each loop, generate a loop counter
            2.for each iteration, add counter by 1
            3.insert a conditional branch inst at the end of the loop
            4.if the counter smaller than the max-loop argument
            4.1 insert a function call to run the loop for some times.(need the counter as parameter)
             */
            for (Loop* l: allLoops) {
//                AllocaInst alloca = AllocaInst();
                //Induction variable: an induction variable is a variable that gets increased or decreased by a fixed amount on every iteration of a loop or is a linear function of another induction variable
                //Canonical induction variable: a variable that gets increased or decreased by 1 on every iteration of a loop
                //loop fusion 循环融合
                //loop guard：When compiler cannot prove loop body will execute at least once, it inserts a guard
                //Loop Rotation：Convert a loop into a do/while style loop
                //Loop Epilogue：循环结束语是一个块，将在循环主体完成执行后执行一次
                //check whether two loops are control flow equivalent：checking that the preheader of the first loop dominates the preheader of the second loop
            }
            return true;
        }
    };
}
    

char LoopTrans::ID = 50;

//static cl::opt<string> InputFilename("mypass_option", cl::desc("Specify input filename for mypass"), cl::value_desc("filename"));
static RegisterPass<LoopTrans> X("LT", "Constant iteration Loop Transform Pass");
