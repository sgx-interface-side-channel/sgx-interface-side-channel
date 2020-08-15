#include <iostream>
#include <fstream>

#include <boost/filesystem/operations.hpp>

#include <phasar/DB/ProjectIRDB.h>
#include <phasar/PhasarLLVM/ControlFlow/LLVMBasedICFG.h>
#include <phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IDETaintAnalysis.h>
#include <phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Problems/IFDSTaintAnalysis.h>
#include <phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Solver/IDESolver.h>
#include <phasar/PhasarLLVM/DataFlowSolver/IfdsIde/Solver/IFDSSolver.h>
#include <phasar/PhasarLLVM/Pointer/LLVMPointsToInfo.h>
#include <phasar/PhasarLLVM/TypeHierarchy/LLVMTypeHierarchy.h>
#include <phasar/Utils/Logger.h>

namespace llvm {
class Value;
} // namespace llvm

using namespace psr;

int main(int argc, const char **argv) {
  initializeLogger(false);
  auto &lg = lg::get();
  if (argc < 2 || !boost::filesystem::exists(argv[1]) ||
      boost::filesystem::is_directory(argv[1])) {
    std::cerr << "sgxtaintusingphasar\n"
                 "A PhASAR-based taint-analysis program\n\n"
                 "Usage: sgxtaintusingphasar <LLVM IR file> <source sink function json file path>\n";
    return 1;
  }
  initializeLogger(false);
  ProjectIRDB DB({argv[1]});
  //TODO: hard-coded here
  TaintConfiguration<const llvm::Value *> TSF("/home/zxh/Desktop/sgx_interface_side_channel/phasar_modified/config/phasar-source-sink-function.json");
  if (auto F = DB.getFunctionDefinition("main")) {
    LLVMTypeHierarchy H(DB);
    // print type hierarchy
    H.print();
    LLVMPointsToInfo P(DB);
    // print points-to information
    P.print();
    LLVMBasedICFG I(DB, CallGraphAnalysisType::OTF, {"main"}, &H, &P);
    // print inter-procedural control-flow graph
    I.print();
    // IFDS template parametrization test
    std::cout << "Testing IFDS:\n";
    IFDSTaintAnalysis L(&DB, &H, &I, &P, TSF,{"main"});
    IFDSSolver<IFDSTaintAnalysis::n_t, IFDSTaintAnalysis::d_t,
            IFDSTaintAnalysis::f_t, IFDSTaintAnalysis::t_t,
            IFDSTaintAnalysis::v_t, IFDSTaintAnalysis::i_t>
        S(L);
    S.solve();
    S.dumpResults();
    // IDE template parametrization test
//    std::cout << "Testing IDE:\n";
//    IDETaintAnalysis M(&DB, &H, &I, &P, {"main"});
//    IDESolver<IDETaintAnalysis::n_t, IDETaintAnalysis::d_t,
//            IDETaintAnalysis::f_t, IDETaintAnalysis::t_t,
//            IDETaintAnalysis::v_t, IDETaintAnalysis::l_t,
//            IDETaintAnalysis::i_t>
//        T(M);
//    T.solve();
//    T.dumpResults();
  } else {
    std::cerr << "error: file does not contain a 'main' function!\n";
  }
  return 0;
}
