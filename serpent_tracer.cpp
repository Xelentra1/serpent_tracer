#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <sstream>

PIN_LOCK logLock;  // Pin lock for thread-safe logging

std::ofstream* outFile = nullptr;

bool g_tracing_enabled = false;
bool g_after_start_addr = false;
bool g_stop_tracing = false;

const ADDRINT START_ADDR = 0x140001649;
const ADDRINT PRINT_WRONG_KEY_ADDR = 0x1400011f0;
const ADDRINT PRINT_FLAG_ADDR = 0x1400011b0;
INT32 g_instructions_after_hlt = 0;

// Fixed buffer for instruction bytes
static UINT8 g_inst_buffer[16];

// Command line switches
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
	"o", "hlt_trace.out", "Output file name");

KNOB<bool> KnobCleanTrace(KNOB_MODE_WRITEONCE, "pintool",
	"clean", "0", "Enable clean trace (filters out unwanted instructions)");

// Utility function to write trace
VOID LogTrace(const std::string& msg) {
	PIN_GetLock(&logLock, 1);

	std::cout << msg << std::endl;
	if (outFile && outFile->is_open()) {
		*outFile << msg << std::endl;
		outFile->flush();
	}

	PIN_ReleaseLock(&logLock);
}

// Initialize logging and lock at program start
void InitializeLogging() {
	PIN_InitLock(&logLock);  // Initialize the Pin lock
	outFile = new std::ofstream(KnobOutputFile.Value().c_str());
}

// Format address as hex
std::string FormatAddress(ADDRINT addr) {
	std::stringstream ss;
	ss << "0x" << std::hex << std::setw(8) << std::setfill('0') << addr;
	return ss.str();
}

// Exception handling callback
EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo,
	PHYSICAL_CONTEXT* pPhysCtxt, VOID* v) {
	ADDRINT exceptAddr = PIN_GetExceptionAddress(pExceptInfo);
	ADDRINT nextAddr = PIN_GetPhysicalContextReg(pPhysCtxt, REG_INST_PTR);

	std::stringstream ss;
	ss << "Exception at " << FormatAddress(exceptAddr);
	LogTrace(ss.str());

	ss.str("");
	ss << "Next instruction at " << FormatAddress(nextAddr);
	LogTrace(ss.str());

	PIN_RemoveInstrumentation();

	return EHR_UNHANDLED;
}

// Thread-local storage key
TLS_KEY mathOperandKey;

struct MathOperandInfo {
	ADDRINT memAddr;    
	UINT64 memValue;    
	UINT64 result;       
	bool isValid;       
};

struct ANALYSIS_INFO {
	BOOL hasReg;
	ADDRINT regValue;
	std::string regName;
};


VOID GetRegValue(ANALYSIS_INFO* info, ADDRINT regVal, REG reg) {
	info->hasReg = TRUE;
	info->regValue = regVal;
	info->regName = REG_StringShort(reg);
}

VOID SaveMathOperandInfo(THREADID tid, ADDRINT memAddr) {
	MathOperandInfo* info = static_cast<MathOperandInfo*>(PIN_GetThreadData(mathOperandKey, tid));
	if (!info) return;

	info->memAddr = memAddr;
	info->isValid = false;

	if (memAddr != 0) {
		UINT64 value = 0;
		size_t bytesRead = PIN_SafeCopy(&value, reinterpret_cast<VOID*>(memAddr), sizeof(UINT64));
		if (bytesRead == sizeof(UINT64)) {
			info->memValue = value;
			info->isValid = true;
		}
	}
}

VOID SaveMathResult(THREADID tid, UINT64 result) {
	MathOperandInfo* info = static_cast<MathOperandInfo*>(PIN_GetThreadData(mathOperandKey, tid));
	if (!info) return;
	info->result = result;
}

// Function to set a register to zero (directly modifying register value)
VOID SetRegisterToZero(VOID* reg_ref) {
	*static_cast<ADDRINT*>(reg_ref) = 0;
}

enum CleanTraceState {
	TRACE_UNTIL_CALL,
	SKIP_UNTIL_POP,
	TRACE_ONE_AFTER_POP,
	SKIP_UNTIL_RET,
	TRACE_ONE_AFTER_RET
};

CleanTraceState cleanTraceState = TRACE_UNTIL_CALL;

VOID ThreadStart(THREADID tid, CONTEXT* ctxt, INT32 flags, VOID* v) {
	MathOperandInfo* info = new MathOperandInfo();
	info->memAddr = 0;
	info->memValue = 0;
	info->result = 0;
	info->isValid = false;
	PIN_SetThreadData(mathOperandKey, info, tid);
}

VOID ThreadFini(THREADID tid, const CONTEXT* ctxt, INT32 code, VOID* v) {
	MathOperandInfo* info = static_cast<MathOperandInfo*>(PIN_GetThreadData(mathOperandKey, tid));
	delete info;
	PIN_SetThreadData(mathOperandKey, nullptr, tid);
}

BOOL IsSpecialRegister(REG reg) {
	switch (reg) {
	case REG_MXCSR:
	case REG_EFLAGS:
	case REG_FLAGS:
	case REG_STATUS_FLAGS:
		return TRUE;
	default:
		// Check if it's an XMM register
		if (REG_is_xmm(reg)) {
			return TRUE;
		}
		// Check if it's a YMM register
		if (REG_is_ymm(reg)) {
			return TRUE;
		}
		// Check if it's a ZMM register
		if (REG_is_zmm(reg)) {
			return TRUE;
		}
		return FALSE;
	}
}

// Analysis routine for instruction execution
VOID PIN_FAST_ANALYSIS_CALL OnInstruction(VOID* ip, ADDRINT memAddr, BOOL hasMemoryOperand, BOOL isMath, THREADID tid, ANALYSIS_INFO* info) {
	if (!g_tracing_enabled) return;

	ADDRINT addr = reinterpret_cast<ADDRINT>(ip);

	// Get instruction at the current IP
	UINT32 size = 15;  // Maximum x86 instruction size
	PIN_SafeCopy(g_inst_buffer, ip, size);

	// Get instruction info
	xed_state_t dstate;
	xed_state_zero(&dstate);
	xed_state_set_machine_mode(&dstate, XED_MACHINE_MODE_LONG_64);

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);

	xed_error_enum_t xed_error = xed_decode(&xedd, g_inst_buffer, size);

	std::stringstream ss;
	ss << FormatAddress(addr) << ": ";

	int desiredLength = 45;

	// Show bytes up to actual instruction length
	if (xed_error == XED_ERROR_NONE) {
		UINT32 length = xed_decoded_inst_get_length(&xedd);
		for (UINT32 i = 0; i < length; i++) {
			if (i != 0) ss << " ";
			ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(g_inst_buffer[i]);
		}

		std::string currentContent = ss.str();
		int currentLength = currentContent.length();
		int spacesToAdd = desiredLength - currentLength;

		if (spacesToAdd > 0) {
			ss << std::string(spacesToAdd, ' '); // Append the necessary spaces
		}

		// Add disassembly
		char buffer[64];
		if (xed_format_context(XED_SYNTAX_INTEL, &xedd, buffer, sizeof(buffer), addr, 0, 0)) {
			ss << " | " << buffer;
		}

		if (hasMemoryOperand) {
			ADDRINT memValue;
			PIN_SafeCopy(&memValue, reinterpret_cast<VOID*>(memAddr), sizeof(ADDRINT));

			std::string currentContent2 = ss.str();
			int currentLength2 = currentContent2.length();
			int spacesToAdd2 = 90 - currentLength2;

			if (spacesToAdd2 > 0) {
				ss << std::string(spacesToAdd2, ' '); // Append the necessary spaces
			}

			if (info->hasReg) {
				ss << "| " << info->regName << " = " << std::hex << info->regValue;
			}

			if (isMath) {
				MathOperandInfo* mathInfo = static_cast<MathOperandInfo*>(PIN_GetThreadData(mathOperandKey, tid));
				if (mathInfo && mathInfo->isValid) {
					ss << ", [" << std::hex << mathInfo->memAddr << "] = " << std::hex << mathInfo->memValue << ", result = " << mathInfo->result;
				}
			}
			else {
				ss << ", [" << std::hex << memAddr << "] = " << std::hex << memValue;
			}
		}
	}
	LogTrace(ss.str());
}


// Instrument instruction
VOID Instruction(INS ins, VOID* v) {
	ADDRINT addr = INS_Address(ins);
	
	if (addr == PRINT_WRONG_KEY_ADDR) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogTrace, IARG_PTR, new std::string("Reached PRINT_WRONG_KEY_ADDR - Stopping all tracing"), IARG_END);
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)([]() {
			g_stop_tracing = true;
			PIN_RemoveInstrumentation();  // Stop further instrumentation
			PIN_ExitApplication(0); // Terminate immediately after logging the message
		}), IARG_END);
		return;
	}

	if (addr == PRINT_FLAG_ADDR) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogTrace, IARG_PTR, new std::string("Reached PRINT_FLAG_ADDR - Stopping all tracing"), IARG_END);
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)([]() {
			g_stop_tracing = true;
			PIN_RemoveInstrumentation();  // Stop further instrumentation
			PIN_ExitApplication(0); // Terminate immediately after logging the message
		}), IARG_END);
		return;
	}

	// Start address
	if (addr == START_ADDR && !g_stop_tracing) {
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogTrace,IARG_PTR, new std::string("Starting trace"),IARG_END);
	   
		g_tracing_enabled = true;
		g_after_start_addr = true;
	}

	// For HLT instruction
	if (INS_Opcode(ins) == XED_ICLASS_HLT && !g_stop_tracing) {
		std::string spaces = "                                  ";
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogTrace, IARG_PTR, new std::string(FormatAddress(addr) + ": " + spaces + "| hlt      - Pausing trace"), IARG_END);
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)([]() { g_tracing_enabled = false; }), IARG_END);
	}

	// For CALL RAX located at addr ending on 0x28bd
	if ((addr & 0xFFFF) == 0x28bd && !g_tracing_enabled && g_after_start_addr && !g_stop_tracing) {
		std::string spaces = "                              ";
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogTrace, IARG_PTR, new std::string(FormatAddress(addr) + ": " + spaces + "| call rax - Restarting trace\n"), IARG_END);
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)([]() { g_tracing_enabled = true; cleanTraceState = TRACE_UNTIL_CALL; }), IARG_END);
	}

	// Convert the address to a string and check the prefix
	std::string addrStr = FormatAddress(addr);
	bool addrStartsWith7FFF = (addrStr.substr(0, 6) == "0x7fff");

	if (!addrStartsWith7FFF && !g_stop_tracing) {
		if (KnobCleanTrace) {
			if (cleanTraceState == TRACE_UNTIL_CALL && INS_IsCall(ins)) {
				cleanTraceState = SKIP_UNTIL_POP;
				return;
			}
			else if (cleanTraceState == SKIP_UNTIL_POP) {
				if (INS_Mnemonic(ins) == "POP" && INS_OperandReg(ins, 0) == REG_RAX) {
					cleanTraceState = TRACE_ONE_AFTER_POP;
				}
				return;
			}
			else if (cleanTraceState == TRACE_ONE_AFTER_POP) {
				cleanTraceState = SKIP_UNTIL_RET;
			}
			else if (cleanTraceState == SKIP_UNTIL_RET) {
				if (INS_IsRet(ins)) {
					cleanTraceState = TRACE_UNTIL_CALL;
				}
				return;
			}
		}

		if (INS_IsMemoryRead(ins)) {
			ANALYSIS_INFO* info = new ANALYSIS_INFO();
			info->hasReg = FALSE;
			info->regValue = 0;

			REG regOp = REG_INVALID();
			for (UINT32 i = 0; i < INS_OperandCount(ins); i++) {
				if (INS_OperandIsReg(ins, i) && !INS_OperandIsMemory(ins, i)) {
					regOp = INS_OperandReg(ins, i);
					break;
				}
			}

			if (REG_valid(regOp) && !IsSpecialRegister(regOp)) {
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)GetRegValue, IARG_PTR, info, IARG_REG_VALUE, regOp, IARG_ADDRINT, regOp, IARG_END);
			}

			if (INS_Mnemonic(ins) == "MUL" || INS_Mnemonic(ins) == "SUB" || INS_Mnemonic(ins) == "XOR" || INS_Mnemonic(ins) == "ADD") {
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)SaveMathOperandInfo, IARG_THREAD_ID, IARG_MEMORYREAD_EA, IARG_END);
				INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)SaveMathResult, IARG_THREAD_ID, IARG_REG_VALUE, REG_RAX, IARG_END);
				INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)OnInstruction, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_ADDRINT, 0, IARG_BOOL, true, IARG_BOOL, true, IARG_THREAD_ID, IARG_PTR, info, IARG_END);
			}
			else {
			    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnInstruction, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_BOOL, true, IARG_BOOL, false, IARG_THREAD_ID, IARG_PTR, info, IARG_END);
			}

		}
		else {
			ANALYSIS_INFO* info = new ANALYSIS_INFO();
			info->hasReg = FALSE;
			info->regValue = 0;

			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)OnInstruction, IARG_FAST_ANALYSIS_CALL, IARG_INST_PTR, IARG_ADDRINT, 0, IARG_BOOL, false, IARG_BOOL, false, IARG_THREAD_ID, IARG_PTR, info, IARG_END);
		}
	}


	// Check for `test <reg>, <reg>` and modify register if needed
	if (!addrStartsWith7FFF && INS_Mnemonic(ins) == "TEST" && INS_OperandCount(ins) >= 2 && g_tracing_enabled && g_after_start_addr && !g_stop_tracing) {
		// Ensure both operands are registers and are the same
		if (INS_OperandIsReg(ins, 0) && INS_OperandIsReg(ins, 1) &&
			INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1)) {

			REG reg = INS_OperandReg(ins, 0);

			// Insert call to modify the register to zero using IARG_REG_REFERENCE
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)SetRegisterToZero, IARG_REG_REFERENCE, reg, IARG_END);

			// Log this modification
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)LogTrace, IARG_PTR, new std::string("Modifying register " + REG_StringShort(reg) + " to zero at " + FormatAddress(addr)), IARG_END);
		}
	}
}

VOID Fini(INT32 code, VOID* v) {
	LogTrace("Tracing finished");
	if (outFile) {
		outFile->close();
		delete outFile;
	}
}

int main(int argc, char* argv[]) {
	PIN_InitSymbols();
	if (PIN_Init(argc, argv)) return -1;

	InitializeLogging();  // Initialize logging with Pin lock

	outFile = new std::ofstream(KnobOutputFile.Value().c_str());

	// Initialize the TLS key for math operand info
	mathOperandKey = PIN_CreateThreadDataKey(nullptr);

	// Add callbacks for thread start/end
	PIN_AddThreadStartFunction(ThreadStart, nullptr);
	PIN_AddThreadFiniFunction(ThreadFini, nullptr);

	PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddFiniFunction(Fini, 0);

	LogTrace("Starting HLT exception tracer...");

	PIN_StartProgram();
	return 0;
}

// pin.exe -smc_strict 1 -t serpent_tracer.dll -- serpentine.exe abcdefghijklmnopqrstuvwxyzABCDEF
// pin.exe -smc_strict 1 -t serpent_tracer.dll -clean 1 -- serpentine.exe abcdefghijklmnopqrstuvwxyzABCDEF