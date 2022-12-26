;volatile: rax, rcx, rdx, r8, r9, r10, r11
;Non-volatile: rbx, rsi, rdi, rbp, r12, r13, r14, r15


;.code

MySegment segment read execute

;Function Prototype: void* DllModuleBaseFinder_(char* ModuleName, unsigned int LenModuleName);
DllModuleBaseFinder_ proc

;check the name of the dll to find
	push rsi
	push rdi
	xor r8, r8
	xor r9, r9
	xor r10, r10
	xor r11, r11

	mov r8, gs:[30h]									;retrieve address of TEB
	mov r9, [r8+60h]									; store PEB address
	mov r10, qword ptr [r9+18h]							; pointer to _PEB_LDR_DATA
	mov r8, qword ptr [r10+10h]							; pointer to InLoadOrderModuleList
	mov r9, rcx											; pointer ntdll string

DO_AGAIN:
	mov r10, qword ptr [r8+60h]							; address of Buffer inside struct FullDllName embedded inside _LDR_DATA_TABLE_ENTRY struct										 
	mov rsi, r9
	mov rdi, r10										; pointer retrieved module name
	mov rcx, rdx										; length of string
	cld													; clear direction flag, will cause ESI and EDI to be incremented during string operation
	repe cmpsw											; compare string byte by byte
	jrcxz GetBaseAddressDll								; jump when end of string reached
	mov r8, qword ptr[r8]								; repeat comparison if library name not found
	jmp DO_AGAIN

GetBaseAddressDll:
;get the base address of the dll
	mov rax, qword ptr [r8+30h]							; move the base address of the dll 
	pop rdi
	pop rsi
	ret
	
DllModuleBaseFinder_ endp

;Function Prototype: int SyscallBaseFinder_(unsigned long long ReturnedDllBase, char* NtApiName, size_t LenNtApiName);
SyscallBaseFinder_ proc

	push rbx
	push r12
	push r13
	
	xor r9, r9
	xor r10, r10
	xor r11, r11
	
	lea r9, [rcx]											;save DllBaseAddr
	lea r13, [rdx]											;save pointer NtApiName
	mov rbx, r8												;save len

	mov r10d, dword ptr [r9+03ch]							;r8+3ch = e_lfanew (offset to NT Header)
	
	mov r11d, dword ptr [r9+r10+018h+070h]					;base + [base+3ch] + 18h + 70h = pointer to export table
	lea r11, [r9+r11]										;Virtual address Export Table
	mov r12d, dword ptr [r11+020h]							;pointer to function names array
	lea r12, [r9+r12]
	xor rdx, rdx

RepeatCheck:
	mov edi, dword ptr [r12+rdx*4]							;address of name of the first API
	lea rdi, [r9+rdi]										;address of API name
	lea rsi, [r13]											;reload rsi with API name
	
	mov rcx, r8
	cld	
	repe cmpsb 												;compare passed API name with API name in export table -> Address of Names Array				
	jrcxz ApiFound
	inc rdx
	jmp RepeatCheck
	
; provide exit condition if API name not found	
	
ApiFound:
	mov r10d, dword ptr [r11+024h]							;Virtual offset Address of name ordinals field
	lea r10, [r9+r10]										;pointer to array address of name ordinals 
	mov r12w, word ptr[r10+rdx*2]							;ordinal number
	movzx r12, r12w
	
	mov r10d, dword ptr [r11+01ch]							;Virtual offset Address of Functions name field
	lea r10, [r9+r10]										;pointer to function array	
	
	mov r10d, dword ptr[r10+r12*4]							; Api Address VirtualOffset
	lea r10, [r9+r10]
	mov rax, r10
 	
	
	pop r13
	pop r12
	pop rbx
	ret
	
SyscallBaseFinder_ endp

Mysegment ends

end