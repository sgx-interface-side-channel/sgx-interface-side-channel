#include "llvm/Pass.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRPrintingPasses.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/FormattedStream.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/LineIterator.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/InstIterator.h"
#include <map>
#include <iostream>
#include <iterator>
using namespace llvm;

/*
 1.先读取记录所有的ecall中的out和usercheck指针
 2.sgx library中的encryption函数，在前面加上padding
 sgx_aes_ctr
 */
// TODO: indirect call
void SplitString(const std::string& s, std::vector<std::string>& v, const std::string& c)
{
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while(std::string::npos != pos2)
    {
        v.push_back(s.substr(pos1, pos2-pos1));
        
        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if(pos1 != s.length())
        v.push_back(s.substr(pos1));
}

namespace {
  struct ConstantSizePass : public ModulePass {
    static char ID;
    ConstantSizePass() : ModulePass(ID) {}
      
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

    bool sgx_debug = false;
      //解析文件，获取ecall列表和ocall列表
    static bool parse_file(std::vector<std::string> *ecall_list,
            std::map<std::string, std::string> *ecall_map,
            std::vector<std::string> *enc_function)
    {
        const std::string ecall_string = "ecall";
//        const std::string ocall_string = "ocall";
        //将文件读取进来
        auto file = MemoryBuffer::getFile("sgx_eocalls_log.txt");
        if (std::error_code EC = file.getError()) {
            errs() << "Could not open sgx_eocalls_log.txt\n";
            return false;
        }
        
        errs() << "Successfully open sgx_eocalls_log.txt\n";
        line_iterator L(*file.get());
//        std::map<std::string, std::string> ecall_map;

        while (!L.is_at_end()) {
            if (!(*L).str().compare(":")||!(*L).str().compare(",")) {
                errs() << "wrong format of sgx_eocalls_log.txt\n";
                return false;
            }

            std::vector<std::string> split_1,split_2;
            std::string s = (*L).str();
            SplitString(s, split_1, ":");
            if (split_1.size()!=2) {
                errs() << "wrong format of sgx_eocalls_log.txt\n";
                return false;
            }
            if(split_1[0]=="ecryptfunc"){
                enc_function->push_back(split_1[1]);
            }else{
                SplitString(split_1[1],split_2, ",");
                if (split_2.size()==1) {
                    ecall_map->insert(std::pair<std::string, std::string>(split_1[0],split_2[0]));
                    (*ecall_list).push_back(split_1[0]);
                    ++L;
                }else{
                    //Todo: deal with multiple sensitive parameter
                }
            }
        }
//
//        if (L.is_at_end() || (*L).str().compare(ocall_string)) {
//            errs() << "wrong format of sgx_eocalls_log.txt\n";
//            return false;
//        }
//
//        ++L;
//        while (!L.is_at_end()) {
//            (*ocall_list).push_back((*L).str());
//            ++L;
//        }

        return true;
    }

    virtual bool runOnModule(Module &M) {
      LLVMContext &ctx = M.getContext();
      std::vector<Function*> enc_functions;
      std::error_code ec;
      raw_fd_ostream log("sgx_functions_log.txt", ec, sys::fs::F_Append);
      Function *fijndael_Enc_Func = M.getFunction("sgx_rijndael128GCM_encrypt");
      Function *aes_Enc_Func = M.getFunction("sgx_aes_ctr_encrypt");
      std::string mangled_cal;
      raw_string_ostream mangled_calStream(mangled_cal);
      Mangler::getNameWithPrefix(mangled_calStream,"CalculateSize",M.getDataLayout());
      mangled_calStream.flush();
      Function *calsize_Func = M.getFunction(mangled_cal);
      Function *malloc_Func = M.getFunction("malloc");
      enc_functions.push_back(fijndael_Enc_Func);
      enc_functions.push_back(aes_Enc_Func);
      std::vector<std::string> ecall_list,self_enc_functions;
      std::map<std::string, std::string> ecall_map;
      //get the 2nd and the 3rd parameter
      //pass these parameters to this function
        std::string mangledName;
        raw_string_ostream mangledNameStream(mangledName);
        Mangler::getNameWithPrefix(mangledNameStream,"Constantize",M.getDataLayout());
        mangledNameStream.flush();
      FunctionCallee myFunc = M.getFunction(mangledName);
      Function *my_constant_func = &cast<Function>(myFunc);
      if (!parse_file(&ecall_list, &ecall_map,&self_enc_functions)) {
          errs() << "Parsing sgx_eocalls_log.txt failed.\n";
      }
        for (const std::string& i : self_enc_functions) {
            std::string mangledName;
            raw_string_ostream mangledNameStream(mangledName);
            Mangler::getNameWithPrefix(mangledNameStream, i,M.getDataLayout());
            mangledNameStream.flush();
            Function *self_Enc_Func = M.getFunction(mangledName);
            enc_functions.push_back(self_Enc_Func);
        }
        #if 0 // For debugging.
              errs() << "ecall list:\n";
              for (std::vector<std::string>::iterator ei = ecall_list.begin();
                                                      ei != ecall_list.end(); ei++) {
                  errs() << *ei << "\n";
              }
        #endif
      // Type Definitions
      PointerType* type_ptr_int8  = PointerType::get(Type::getInt8Ty(ctx), 0);
      // Find out the functions to be modified.
//      std::vector<Function*> fun_list;
      for (auto&F : M) {
        if (sgx_debug) errs() << "Function: " << F.getName() << " ... ";
        // Skip if the function is forward declared or an ocall.
        // Hard-coded here for skipping sgx_init function.
        if (F.empty() ||
            F.getName().str() == "sgx_init") {
          if (sgx_debug) errs() << "skip\n";
          continue;
        }
        if (std::find(ecall_list.begin(), ecall_list.end(), F.getName().str()) != ecall_list.end()) {
            log << F.getName().str() << "\n";
            if (sgx_debug) errs() << "target function\n";
            for(inst_iterator iter = inst_begin(F); iter != inst_end(F); ++iter){
                if (isa<CallInst>(*iter)) {
                    auto *this_call_ins = (CallInst*)&(*iter);
                    Function *called_func = this_call_ins->getCalledFunction();
                    if (called_func){
                        if(std::count(enc_functions.begin(), enc_functions.end(), called_func)){
                            // check if the variable is in the list
//                            called_func->getOperandList();
                            //remove the prefix "sgx_"
//                            auto map_iter = ecall_map.find(F.getName().substr(4,std::string::npos));
                            std::vector<Value *> cal_args;
                            cal_args.push_back(this_call_ins->getOperand(2));
                            Instruction *Call_calculate = CallInst::Create(calsize_Func, cal_args, "call_calculate");
                            dyn_cast<Instruction>(this_call_ins)->insertBefore(Call_calculate);
                            std::vector<Value *> malloc_args;
                            malloc_args.push_back(Call_calculate);
                            Instruction *Call_malloc = CallInst::Create(malloc_Func, malloc_args, "call_malloc");
                            dyn_cast<Instruction>(this_call_ins)->insertBefore(Call_malloc);
                            std::vector<Value *> args;
                            args.push_back(this_call_ins->getArgOperand(1));
                            args.push_back(this_call_ins->getArgOperand(2));
                            args.push_back(Call_malloc);
                            args.push_back(Call_calculate);
                            ArrayRef< Value* > arguments(args);
                            Instruction *Call_Constant_Inst = CallInst::Create(my_constant_func, arguments, "call_constant");
                            dyn_cast<Instruction>(this_call_ins)->insertBefore(Call_Constant_Inst);
                            this_call_ins->setOperand(1,malloc_Func);
                            this_call_ins->setOperand(2,Call_calculate);
                            errs() << "Inserted the function!\n";
                        };}
                    else
                        log << StringRef("indirect call") << "\n";
                    
                }
            }
        }
      }
      errs() << "-----Function Wrapper done-----\n";

      log.close();

      return false;
    }
  };
}

char ConstantSizePass::ID = 0;

static RegisterPass<ConstantSizePass> X("function-wrapper", "TSX transformation");

