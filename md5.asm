; ^-^ ;

section .rodata
    ; MD5 constants
    align 4
    constants:
        dd 3614090360, 3905402710,  606105819, 3250441966
        dd 4118548399, 1200080426, 2821735955, 4249261313
        dd 1770035416, 2336552879, 4294925233, 2304563134
        dd 1804603682, 4254626195, 2792965006, 1236535329
        dd 4129170786, 3225465664,  643717713, 3921069994
        dd 3593408605,   38016083, 3634488961, 3889429448
        dd 568446438,  3275163606, 4107603335, 1163531501
        dd 2850285829, 4243563512, 1735328473, 2368359562
        dd 4294588738, 2272392833, 1839030562, 4259657740
        dd 2763975236, 1272893353, 4139469664, 3200236656
        dd 681279174,  3936430074, 3572445317,   76029189
        dd 3654602809, 3873151461,  530742520, 3299628645
        dd 4096336452, 1126891415, 2878612391, 4237533241
        dd 1700485571, 2399980690, 4293915773, 2240044497
        dd 1873313359, 4264355552, 2734768916, 1309151649
        dd 4149444226, 3174756917,  718787259, 3951481745
    
    ; MD5 shift amounts
    shifts:
        db  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22
        db  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20
        db  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23
        db  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
    
    ; MD5 message offsets
    offsets:
        db  0,  4,  8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
        db  4, 24, 44,  0, 20, 40, 60, 16, 36, 56, 12, 32, 52,  8, 28, 48,
        db 20, 32, 44, 56,  4, 16, 28, 40, 52,  0, 12, 24, 36, 48, 60,  8,
        db  0, 28, 56, 20, 48, 12, 40,  4, 32, 60, 24, 52, 16, 44,  8, 36


section .text
    global MD5_UPDATE  ; Update the MD5 hash
    global MD5_DIGEST  ; Digest the MD5 hash

;
; States struct:
; {
;     uint32_t a
;     uint32_t b
;     uint32_t c
;     uint32_t d
;     uint32_t blocks
;     uint8_t  todo_len
;     char     todo[128]
; }
;
;
; Digest struct:
; {
;     uint32_t a
;     uint32_t b
;     uint32_t c
;     uint32_t d
;     uint8_t  canary
; }
;

MD5_DIGEST:
    ; Args:
    ; rdi - digest (the digest struct)
    ; rsi - states (the states struct)

    ; Copy the current hash states to the digest states to update them while preserving the original hash states
    mov qword rax, [rsi]     ; Move the first two 32-bit numbers
    mov [rdi], qword rax
    mov qword rax, [rsi + 8] ; Move the last two 32-bit numbers
    mov [rdi + 8], qword rax
    mov [rdi + 16], byte 0xFF ; Set a canary to prevent automatically attempting to store remaining message data

    mov r10, rdi ; Preserve the digest struct on r10

    movzx rax, byte [rsi + 16] ; Fetch the todo length

    xor r8,  r8         ; Clear the r8 register to have the upper 32 bits empty
    mov r8d, [rsi + 17] ; Fetch the number of blocks

    ; Preserve the message pointer on r9. Add 21 to start at the todo buffer
    lea r9, [rsi + 21]

    shl r8, 6 ; Multiply the number of blocks by 64 to get the length (without the todo, will be added later)

    lea rsi, [r9 + rax] ; Add the todo length to start after the todo

    add r8, rax ; Add the todo length to the full length to get the actual total length

    mov [rsi], byte 0x80 ; Set the 0x80 byte

    shl r8, 3 ; Multiply the length (in bytes) by 8 to get it in bits

    ; Move the offset of after the todo and the 0x80 byte to the destination index for zeroing
    lea rdi, [rsi + 1]

    cmp rax, 56          ; Compare the todo length to 56
    js  digest_one_chunk ; We only need 1 chunk if less than 56

    ; Otherwise we need two chunks, but the code flows there directly, so don't jump

    ; The number of bytes to pad with zeroes is calculated by taking the full
    ; buffer length (64 or 128), decreasing by 9 as those are used by the
    ; 0x80 byte and the bit length, and add 8 to avoid having to increment
    ; the result. The excess bytes padded by this don't matter as they won't
    ; overflow and will be overwritten anyway, and setting per 8 is faster.

digest_two_chunks:
    mov rcx, 127 ; Set the number of bytes to pad as 127
    sub rcx, rax ; Subtract the todo length to get the bytes to zero out

    xor rax, rax ; Clear rax so that it's set to zero (otherwise the value of rax will be copied)

    shr rcx, 3 ; Divide the number by 8 to get how many chunks of 8 to pad

    rep stosq  ; Zero out the chunks of 8 in the todo

    mov [r9 + 120], qword r8 ; Place the bit length at the top of the buffer

    mov rdi, r10   ; Retrieve the digest pointer and set it on rdi
    mov rsi, r9    ; Set the message as the todo buffer, which was preserved on r9
    mov rdx, 128   ; Set the length of 2 chunks
    jmp md5_rounds ; Digest the message

digest_one_chunk:
    mov rcx, 63  ; Set the number of bytes to pad as 63
    sub rcx, rax ; Subtract the todo length to get the bytes to zero out

    xor rax, rax ; Clear rax so that it's set to zero (otherwise the value of rax will be copied)

    shr rcx, 3 ; Divide the number by 8 to get how many chunks of 8 to pad

    rep stosq  ; Zero out the chunks of 8 in the todo

    mov [r9 + 56], qword r8 ; Place the bit length at the top of the buffer

    mov rdi, r10   ; Retrieve the digest pointer and set it on rdi
    mov rsi, r9    ; Set the message as the todo buffer
    mov rdx, 64    ; Set the length of 1 chunk
    jmp md5_rounds ; Digest the message


MD5_UPDATE:
    ; Args:
    ; rdi - states   (the states struct)
    ; rsi - message  (the message to process)
    ; rdx - length   (the length of the message)

    ; Check whether we can process the message and the todo combined
    movzx rax, byte [rdi + 16] ; Fetch the todo length
    test  rax, rax             ; Check the todo length
    jz    correct_pointer      ; Update without todo if it's zero

    mov r9, rdi ; Preserve the states pointer

    sub rsi, rax        ; Subtract rax from rsi to start at the todo length
    mov rdi, rsi        ; Move the message pointer to the destination index
    mov r8,  rsi        ; Preserve the message pointer in r8 as it's incremented by the copy instructions
    lea rsi, [r9 + 21]  ; Set the todo buffer of the states struct as the source index

    ; Copy the todo bytes into the message

    mov rcx, rax ; Move the size to rcx for the rep operation
    shr rcx, 3   ; Get the number of 8-byte chunks
    rep movsq    ; Copy the 8-byte chunks into the message

    mov rcx, rax ; Move the original size to rcx again
    and rcx, 7   ; Get the modulus of 8 to get the remaining moves
    rep movsb    ; Move the remaining bytes to the message

    mov rsi, r8  ; Restore the unchanged message pointer

    mov rdi, r9  ; Retrieve the states pointer
    mov rsi, r8  ; Retrieve the message pointer

correct_pointer:
    add rax, rdx ; Add the message length to the todo length to get the total length
    mov rdx, rax ; Store the total length on rdx for the rounds function
    and rax, 63  ; Do the length modulus 64 to get the todo length

    mov [rdi + 16], al ; Set the first byte of rax as the todo length

    ; This automatically jumps to the rounds function


;
; md5_rounds register values:
;
; rdx  - number of blocks (message length on input, gets converted to number of blocks)
; r12  - round iterator
;
; rdi  - pointer to states
; rsi  - pointer to message
; r13  - pointer to constants
; r14  - pointer to offsets
; r15  - pointer to shifts
;
; r8d  - state 1 (a)
; r9d  - state 2 (b)
; r10d - state 3 (c)
; r11d - state 4 (d)
;
; rax  - Used for calculating f
; rbx  - Used to store constants[i]
; rbp  - Used to store offsets[i]
; rcx  - Used to store shifts[i]
;

md5_rounds:
    ; Args:
    ; rdi - states   (the states struct)
    ; rsi - message  (the message to process)
    ; rdx - length   (the message length)

    cmp rdx, 64         ; Check the message length to check if it's at least 1 chunk of 64
    js  store_remaining ; Store the message in the todo buffer

    shr rdx, 6 ; Divide the message length by 64 to get the number of chunks

    add [rdi + 17], edx ; Add the number of chunks to the total processed blocks (32-bit so use edx)

    ; Save current registers
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15

    ; Prepare data addresses
    lea r13, [rel constants]
    lea r14, [rel offsets  ]
    lea r15, [rel shifts   ]

    ; Fetch the 4 states
    mov r8d,  [rdi     ]
    mov r9d,  [rdi +  4]
    mov r10d, [rdi +  8]
    mov r11d, [rdi + 12]

    ; Initialize the round iterator
    mov r12, 0

    ; Jump to the first loop as initialize_loop is for iterations after the first
    jmp loop_round1

initialize_loop:
    mov r12, 0  ; Initialize the round iterator again
    
    ; Fetch the updated states
    mov r8d,  [rdi     ]
    mov r9d,  [rdi +  4]
    mov r10d, [rdi +  8]
    mov r11d, [rdi + 12]

loop_round1:
    cmp r12, 16
    je loop_round2

    ; Calculate f
    ; f = ((c ^ d) & b) ^ d + a + constants[i] + *(uint32_t *)((message) + offsets[i])

    ; Load values from memory
    mov   ebx,      [r13 + 4*r12] ; constants[i]
    movzx rbp, byte [r14 +   r12] ; offsets[i]
    mov   ebp,      [rsi +   rbp] ; message + offsets[i]
    mov   cl,       [r15 +   r12] ; shifts[i]

    ; eax = f
    mov eax, r10d ; f = c
    xor eax, r11d ; f ^ d
    and eax, r9d  ; f & b
    xor eax, r11d ; f ^ d

    add eax, r8d  ; f + a
    add eax, ebx  ; f + constants[i]
    add eax, ebp  ; f + *(uint32_t *)((message) + offsets[i])

    ; Exchange values
    mov r8d,  r11d ; a = d
    mov r11d, r10d ; d = c
    mov r10d, r9d  ; c = b

    ; b += ROL(f, shifts[i])

    rol eax, cl  ; ROL(f, shifts[i])
    add r9d, eax ; b + ROL(f, shifts[i])

    inc r12
    jmp loop_round1

loop_round2:
    cmp r12, 32
    je loop_round3

    ; Calculate f
    ; f = ((b ^ c) & d) ^ c + a + constants[i] + *(uint32_t *)((message) + offsets[i])

    ; Load values from memory
    mov   ebx,      [r13 + 4*r12] ; constants[i]
    movzx rbp, byte [r14 +   r12] ; offsets[i]
    mov   ebp,      [rsi +   rbp] ; message + offsets[i]
    mov   cl,       [r15 +   r12] ; shifts[i]

    ; eax = f
    mov eax, r9d  ; f = b
    xor eax, r10d ; f ^ c
    and eax, r11d ; f & d
    xor eax, r10d ; f ^ c

    add eax, r8d  ; f + a
    add eax, ebx  ; f + constants[i]
    add eax, ebp  ; f + *(uint32_t *)((message) + offsets[i])

    ; Exchange values
    mov r8d,  r11d ; a = d
    mov r11d, r10d ; d = c
    mov r10d, r9d  ; c = b

    ; b += ROL(f, shifts[i])

    rol eax, cl  ; ROL(f, shifts[i])
    add r9d, eax ; b + ROL(f, shifts[i])

    inc r12
    jmp loop_round2

loop_round3:
    cmp r12, 48
    je loop_round4

    ; Calculate f
    ; f = (b ^ c ^ d) + a + constants[i] + *(uint32_t *)((message) + offsets[i])

    ; Load values from memory
    mov   ebx,      [r13 + 4*r12] ; constants[i]
    movzx rbp, byte [r14 +   r12] ; offsets[i]
    mov   ebp,      [rsi +   rbp] ; message + offsets[i]
    mov   cl,       [r15 +   r12] ; shifts[i]

    ; eax = f
    mov eax, r9d  ; f = b
    xor eax, r10d ; f ^ c
    xor eax, r11d ; f ^ d

    add eax, r8d  ; f + a
    add eax, ebx  ; f + constants[i]
    add eax, ebp  ; f + *(uint32_t *)((message) + offsets[i])

    ; Exchange values
    mov r8d,  r11d ; a = d
    mov r11d, r10d ; d = c
    mov r10d, r9d  ; c = b

    ; b += ROL(f, shifts[i])

    rol eax, cl  ; ROL(f, shifts[i])
    add r9d, eax ; b + ROL(f, shifts[i])

    inc r12
    jmp loop_round3

loop_round4:
    cmp r12, 64
    je end_rounds

    ; Calculate f
    ; f = (~d | b) ^ c + a + constants[i] + *(uint32_t *)((message) + offsets[i])

    ; Load values from memory
    mov   ebx,      [r13 + 4*r12] ; constants[i]
    movzx rbp, byte [r14 +   r12] ; offsets[i]
    mov   ebp,      [rsi +   rbp] ; message + offsets[i]
    mov   cl,       [r15 +   r12] ; shifts[i]

    ; eax = f
    mov eax, r11d ; f = d
    not eax       ; f = ~f
    or  eax, r9d  ; f | b
    xor eax, r10d ; f ^ c

    add eax, r8d  ; f + a
    add eax, ebx  ; f + constants[i]
    add eax, ebp  ; f + *(uint32_t *)((message) + offsets[i])

    ; Exchange values
    mov r8d,  r11d ; a = d
    mov r11d, r10d ; d = c
    mov r10d, r9d  ; c = b

    ; b += ROL(f, shifts[i])

    rol eax, cl  ; ROL(f, shifts[i])
    add r9d, eax ; b + ROL(f, shifts[i])

    inc r12
    jmp loop_round4

end_rounds:
    ; Update the current states from the struct
    add [rdi     ], r8d
    add [rdi +  4], r9d
    add [rdi +  8], r10d
    add [rdi + 12], r11d

    dec rdx ; Decrement the number of blocks

    add rsi, 64 ; Add 64 to start at the next message chunk

    ; Check whether we have more rounds to go
    test rdx, rdx        ; Check the amount of operations remaining
    jnz  initialize_loop ; Start a new loop if not zero

    ; Restore old registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx

store_remaining:
    cmp byte [rdi + 16], 0xFF ; Check if there's a canary where the todo length should be
    je  finish                ; Go to the finish if there's a canary (otherwise value won't reach 255)

    lea rdi, [rdi + 21] ; Start at the todo buffer

    mov rcx, 8 ; Copy 8 chunks of 8 to ensure we got all
    rep movsq  ; Copy the 8-byte chunks into the message

finish:
    ; No return value
    ret

