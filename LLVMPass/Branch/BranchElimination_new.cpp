#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringSet.h"
#include "llvm/Analysis/BlockFrequencyInfo.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/Analysis/RegionInfo.h"
#include "llvm/Analysis/RegionIterator.h"
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


using namespace llvm;

#define DEBUG_TYPE "be"

// Function name in the EDL file-> prefix with "sgx_" we will get the function name in enclave_t.c file.
namespace {
    struct BranchElimination : public ModulePass {
    public:
        static char ID;
        BranchElimination() : ModulePass(ID) {
            errs() << "Branch Elimination: \n";
        }

        static int findPosVector(std::vector<Instruction*> &v, Instruction* ins){
//            int index = -1;
            for(int i = 0;i < v.size();++i){
                if(v[i] == ins)
                    return i;
            }
            return -1;
        }
        static unsigned getAlignmentByType(Type *Ty) {
            if (Ty->isIntegerTy()) {
                return cast<IntegerType>(Ty)->getBitWidth() / 8;
            }
            if (Ty->isFloatTy()) {
                return 4;
            }
            if (Ty->isDoubleTy()) {
                return 8;
            }

            return 1;
        }

        bool runOnModule(Module &M){
            LLVMContext &ctx = M.getContext();
            int tmp_index = 0;
            std::vector<Function*> fun_list;
            for (auto&F : M) {
                errs() << "I saw function: " << F.getName() << "\n";
                if (!F.empty()){
                    fun_list.push_back(&F);
                }
            }
            std::vector<Function*> n_fun_list;
            for (std::vector<Function*>::iterator it = fun_list.begin();
                 it != fun_list.end(); ++it) {
                Function *o_fun = *it;

                FunctionType *fun_type = o_fun->getFunctionType();
                StringRef n_fun_name(o_fun->getName());
                std::string n_fun_name_str(o_fun->getName().str());
                o_fun->setName("_" + o_fun->getName());
                Function *n_fun = Function::Create(fun_type, o_fun->getLinkage(), StringRef(n_fun_name_str), &M);
                MDNode *node = MDNode::get(ctx, MDString::get(ctx, "external"));
                n_fun->setMetadata("sgxtsx.fun.info", node);

                // Copy attributes
                AttributeSet n_attrs = n_fun->getAttributes();
                n_fun->copyAttributesFrom(o_fun);
                n_fun->setAttributes(n_attrs);

                // Copy the arguments's name and attributes, 把参数的name和attributes存到n_arg中
                AttributeSet o_attrs = o_fun->getAttributes();
                Function::arg_iterator n_arg = n_fun->arg_begin();
                for (Function::const_arg_iterator o_it = o_fun->arg_begin(), o_end = o_fun->arg_end();
                     o_it != o_end; ++o_it) {
                    AttributeSet attrs = o_attrs.getParamAttributes(o_it->getArgNo() + 1);
                    if (attrs.getNumSlots() > 0)
                        n_arg->addAttr(attrs);
                    n_arg->setName(o_it->getName());
                    n_arg++;
                }
                n_fun->setAttributes(
                        n_fun->getAttributes()
                                .addAttributes(n_fun->getContext(), AttributeSet::ReturnIndex,
                                               o_attrs.getRetAttributes())
                                .addAttributes(n_fun->getContext(), AttributeSet::FunctionIndex,
                                               o_attrs.getFnAttributes()));

                n_fun_list.push_back(n_fun);
            }

            errs() << "-----Function Wrapper Pass start-----\n";
            int fun_index = 0;

            for (std::vector<Function*>::iterator it = n_fun_list.begin();
                 it != n_fun_list.end(); ++it) {
                Function *n_fun = *it;
                BasicBlock* label_entry = BasicBlock::Create(ctx, "entry", n_fun, 0);

                // Get argument list
                std::vector<AllocaInst*> allocinst_list;
                for (Function::arg_iterator n_args = n_fun->arg_begin();
                     n_args != n_fun->arg_end(); ++n_args) {
                    StringRef ptr_name(n_args->getName().str() + ".addr");
                    AllocaInst* ptr_addr = new AllocaInst(n_args->getType(), ptr_name.str(), label_entry);
                    unsigned align = getAlignmentByType(n_args->getType());
                    ptr_addr->setAlignment(align);
                    allocinst_list.push_back(ptr_addr);
                }

                std::vector<AllocaInst*>::iterator alloc_it;
                alloc_it = allocinst_list.begin();
                for (Function::arg_iterator args = n_fun->arg_begin();
                     args != n_fun->arg_end(); ++args) {
                    AllocaInst* allocinst = *alloc_it;
                    StoreInst* store = new StoreInst(args, allocinst, false, label_entry);
                    unsigned align = getAlignmentByType(args->getType());
                    store->setAlignment(align);
                    alloc_it++;
                }

                std::vector<Value*> call_params;
                alloc_it = allocinst_list.begin();
                for (Function::arg_iterator args = n_fun->arg_begin();
                     args != n_fun->arg_end(); ++args) {
                    // Load
                    AllocaInst *allocinst = *alloc_it;
                    LoadInst* load = new LoadInst(allocinst, "", false, label_entry);
                    unsigned align = getAlignmentByType(args->getType());
                    load->setAlignment(align);
                    call_params.push_back(load);
                    alloc_it++;
                }

                Function* callee = M.getFunction(StringRef("_" + n_fun->getName().str()));
                CallInst* call = CallInst::Create(callee, call_params, "", label_entry);
                call->setCallingConv(CallingConv::C);
                call->setTailCall(false);
                AttributeSet call_PAL;
                call->setAttributes(call_PAL);

                Type *ret_type = n_fun->getReturnType();
                if (!ret_type->isVoidTy()) {
                    // Return based on the return type
                    ReturnInst::Create(ctx, call, label_entry);
                } else {
                    // Return void
                    ReturnInst::Create(ctx, label_entry);
                }

                fun_index++;
            }
            errs() << "-----Function Wrapper done-----\n";


            for(inst_iterator iter = inst_begin(F); iter != inst_end(F); ++iter){
                if(isa<BranchInst>(*iter)){
                    auto* ins = (BranchInst*)&(*iter);
                    if(ins->isConditional()){
                        BasicBlock* Bb_true;
                        BasicBlock* Bb_false;
                        Bb_true = ins->getSuccessor(0);
                        Bb_false = ins->getSuccessor(1);
                        BasicBlock::iterator false_iter = Bb_false->begin();
                        BasicBlock::iterator true_iter = Bb_true->end();
                        true_iter--;
                        std::vector<Instruction*> old_true_ins,old_false_ins,new_true_ins,new_false_ins;
                        std::string tmp = "tmp";
                        for(Instruction &ins_1 : *Bb_false){
                            if(!isa<BranchInst>(ins_1)){
                                Instruction* new_inst = ins_1.clone();
                                new_false_ins.push_back(new_inst);
                                old_false_ins.push_back(&ins_1);
                            }
                        }

                        for(Instruction &ins_1 : *Bb_true){
                            if(!isa<BranchInst>(ins_1)){
                                Instruction* new_inst = ins_1.clone();
                                new_true_ins.push_back(new_inst);
                                old_true_ins.push_back(&ins_1);
                                int pos = 0;

                                if(new_inst->getOpcode() == Instruction::Call){
                                    //TODO: no need to change parameters but to change the function
                                    for(Use &u:((CallInst*)&(*new_inst))->arg_operands()){
                                        Value *v = u.get();
                                        int index = findPosVector(old_true_ins,((Instruction*)v));
                                        if (index != -1) {
                                            new_inst->setOperand(pos++, new_true_ins[index]);
                                        }
                                    }
                                }

                                else if (new_inst->getOpcode() == Instruction::Store){
                                    Value *u1 = new_inst->getOperand(0);
                                    Value *u2 = new_inst->getOperand(1);
                                    int index1 = findPosVector(old_true_ins,((Instruction*)u1));
                                    int index2 = findPosVector(old_true_ins,((Instruction*)u2));
                                    if (index1 != -1) {
                                        new_inst->setOperand(pos++, new_true_ins[index1]);
                                    }
                                    if (index2 != -1) {
                                        new_inst->setOperand(pos++, new_true_ins[index1]);
                                    }else if(isa<Constant>(*u1)){
                                        continue;
                                    }else{
                                        LLVMContext &context1 = Bb_false->getContext();
                                        IRBuilder<> builder1(context1);
                                        Type* t = u2->getType();
                                        AllocaInst* allocaInst = builder1.CreateAlloca(t, 0, nullptr, tmp + std::to_string(tmp_index++));
                                        allocaInst->insertBefore(&*false_iter);
                                        new_inst->setOperand(pos++, allocaInst);
                                    }
                                }
                                else if (new_inst->getNumOperands()!=0){
                                    for(Use  &u: new_inst->operands()){
                                        Value *v = u.get();
                                        int index = findPosVector(old_true_ins,((Instruction*)v));
                                        if (index != -1) {
                                            new_inst->setOperand(pos++, new_true_ins[index]);
                                        }
                                    }
                                }
                                Bb_false->getInstList().insert(false_iter, new_inst);
                            }
                        }
                        errs() << "*Bb_false\n" << *Bb_false << "\n";
                        for (Instruction* ins_1 : new_false_ins) {
                            int pos = 0;
                            // Todo： copy a function and modify all the store instructions.
                            if(ins_1->getOpcode() == Instruction::Call){
                                if(!((CallInst*)&(*ins_1))->getCalledFunction()->getName().find("edited_")){
                                    //if we don't find a edited function, then we need to modify it
                                    Function *o_fun = ((CallInst*)&(*ins_1))->getCalledFunction();
                                    FunctionType *fun_type = o_fun->getFunctionType();
                                    StringRef n_fun_name("edited_" + o_fun->getName().str());
//                                    std::string n_fun_name_str(o_fun->getName().str());
//                                    n_fun->setName("edited_" + o_fun->getName());
                                    Function *n_fun = Function::Create(fun_type, o_fun->getLinkage(), n_fun_name, (o_fun->getParent()));
                                    // Copy attributes
                                    AttributeList n_attrs = n_fun->getAttributes();
                                    n_fun->copyAttributesFrom(o_fun);
                                    n_fun->setAttributes(n_attrs);
                                    // Copy the arguments's name and attributes
                                    AttributeList o_attrs = o_fun->getAttributes();
                                    Function::arg_iterator n_arg = n_fun->arg_begin();
                                    ValueToValueMapTy VMap;
                                    for (Function::const_arg_iterator o_it = o_fun->arg_begin(), o_end = o_fun->arg_end();
                                         o_it != o_end; ++o_it) {
                                        VMap[&*o_it] = n_arg;
//                                        AttributeSet attrs = o_attrs.getParamAttributes(o_it->getArgNo() + 1);
                                        AttributeSet attrs = o_attrs.getParamAttributes(o_it->getArgNo() + 1);
                                        if (attrs.getNumAttributes() > 0){
                                            for(Attribute attr: attrs){
                                                n_arg->addAttr(attr);
                                            }
                                        }
                                        n_arg->setName(o_it->getName());
                                        n_arg++;
                                    }
                                    n_fun->setAttributes(
                                            n_fun->getAttributes()
                                                    .addAttributes(n_fun->getContext(), AttributeList::ReturnIndex,
                                                                   o_attrs.getRetAttributes())
                                                    .addAttributes(n_fun->getContext(), AttributeList::FunctionIndex,
                                                                   o_attrs.getFnAttributes()));

                                    SmallVector<ReturnInst*, 8> returns;
                                    CloneFunctionInto(n_fun,o_fun,VMap, true,returns,"_cloned");
                                    ((CallInst*)&(*ins_1))->setCalledFunction(n_fun);
                                }
                                for(Use &u:((CallInst*)&(*ins_1))->arg_operands()){
                                    Value *v = u.get();
                                    int index = findPosVector(old_false_ins,((Instruction*)v));
                                    if (index != -1) {
                                        ins_1->setOperand(pos++, new_false_ins[index]);
                                    }
                                }
                            }
                            else if (ins_1->getOpcode() == Instruction::Store){
                                Value *u1 = ins_1->getOperand(0);
                                Value *u2 = ins_1->getOperand(1);
                                int index1 = findPosVector(old_false_ins,((Instruction*)u1));
                                int index2 = findPosVector(old_false_ins,((Instruction*)u2));
                                if (index1 != -1) {
                                    ins_1->setOperand(pos++, new_false_ins[index1]);
                                }
                                if (index2 != -1) {
                                    ins_1->setOperand(pos++, new_false_ins[index1]);
                                }else if(isa<Constant>(*u1)){
                                    continue;
                                }else{
                                    LLVMContext &context1 = Bb_true->getContext();
                                    IRBuilder<> builder1(context1);
                                    Type* t = u2->getType();
                                    AllocaInst* allocaInst = builder1.CreateAlloca(t, 0, nullptr, tmp + std::to_string(tmp_index++));
                                    allocaInst->insertBefore(&*true_iter);
                                    ins_1->setOperand(pos++, allocaInst);
                                }
                            }
                            else if (ins_1->getNumOperands()!=0){
                                for(Use  &u: ins_1->operands()){
                                    Value *v = u.get();
                                    int index = findPosVector(old_false_ins,((Instruction*)v));
                                    if (index != -1) {
                                        ins_1->setOperand(pos++, new_false_ins[index]);
                                    }
                                }
                            }
                            Bb_true->getInstList().insert(true_iter, ins_1);
                        }
                        errs() << "*Bb_true\n" << *Bb_true << "\n";
                    }
                }
            }
            return true;
        }
    };
} // end anonymous namespace

char BranchElimination::ID = 50;

static RegisterPass<BranchElimination> X("BE", "Branch Elimination");
