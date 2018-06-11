#pragma once
////////////////////////////////
// DisassembleMem32
////////////////////////////////
DWORD DisassembleMem32(PBYTE pbCode)
{
	BYTE bmodrm = *pbCode;

	if (bmodrm >= 0xC0)
		return 1;

	if (bmodrm >= 0x80)
		return ((bmodrm & 0x07) == 0x04 ? 6 : 5);

	if (bmodrm >= 0x40)
		return ((bmodrm & 0x07) == 0x04 ? 3 : 2);

	if ((bmodrm & 0x07) == 0x05)
		return 5;

	if ((bmodrm & 0x07) == 0x04)
		return ((pbCode[1] & 0x07) == 0x05 ? 6 : 2);

	return 1;
} //DisassembleMem32()


////////////////////////////////
// DisassembleProlog
////////////////////////////////


DWORD DisassembleProlog(
	PBYTE pbCode, // Byte String to be disassembled
	DWORD cbMinimumRequired // Minimum length of code cavity required
	)
{
	PBYTE pb;
	DWORD cboperand;

	//----------------
	cboperand = 4;

	for (pb = pbCode; (DWORD)(pb - pbCode) < cbMinimumRequired;)
	{
		// Potemkin's Hackers Group rocks heavy metal-style (OPCODE.LST)

		switch (*pb++)
		{
		case 0x00: // 00h: ADD mem8, reg8
		case 0x01: // 01h: ADD mem, reg
		case 0x02: // 02h: ADD reg8, mem8
		case 0x03: // 03h: ADD reg, mem
		case 0x08: // 08h: OR mem8, reg8
		case 0x09: // 09h: OR mem, reg
		case 0x0A: // 0Ah: OR reg8, mem8
		case 0x0B: // 0Bh: OR reg, mem
		case 0x10: // 10h: ADC mem8, reg8
		case 0x11: // 11h: ADC mem, reg
		case 0x12: // 12h: ADC reg8, mem8
		case 0x13: // 13h: ADC reg, mem
		case 0x18: // 18h: SBB mem8, reg8
		case 0x19: // 19h: SBB mem, reg
		case 0x1A: // 1Ah: SBB reg8, mem8
		case 0x1B: // 1Bh: SBB reg, mem
		case 0x20: // 20h: AND mem8, reg8
		case 0x21: // 21h: AND mem, reg
		case 0x22: // 22h: AND reg8, mem8
		case 0x23: // 23h: AND reg, mem
		case 0x28: // 28h: SUB mem8, reg8
		case 0x29: // 29h: SUB mem, reg
		case 0x2A: // 2Ah: SUB reg8, mem8
		case 0x2B: // 2Bh: SUB reg, mem
		case 0x30: // 30h: XOR mem8, reg8
		case 0x31: // 31h: XOR mem, reg
		case 0x32: // 32h: XOR reg8, mem8
		case 0x33: // 33h: XOR reg, mem
		case 0x38: // 38h: CMP mem8, reg8
		case 0x39: // 39h: CMP mem, reg
		case 0x3A: // 3Ah: CMP reg8, mem8
		case 0x3B: // 3Bh: CMP reg, mem
		case 0x84: // 84h: TEST mem8, reg8
		case 0x85: // 85h: TEST mem, reg
		case 0x86: // 86h: XCHG mem8, reg8
		case 0x87: // 87h: XCHG mem, reg
		case 0x88: // 88h: MOV mem8, reg8
		case 0x89: // 89h: MOV mem, reg
		case 0x8A: // 8Ah: MOV reg8, mem8
		case 0x8B: // 8Bh: MOV reg, mem
		case 0x8C: // 8Ch: <op> mem, sreg
		case 0x8D: // 8Dh: LEA reg, mem
		case 0x8E: // 8Eh: <op> sreg, mem
		case 0x8F: // 8Fh: POP mem
		case 0xC4: // C4h: LES reg, mem
		case 0xC5: // C5h: LDS reg, mem
		case 0xD0: // D0h: <op> mem8, 1
		case 0xD1: // D1h: <op> mem, 1
		case 0xD2: // D2h: <op> mem8, CL
		case 0xD3: // D3h: <op> mem, CL
		case 0xFE: // FEh: <op> mem8
		case 0xFF: // FFh: <op> mem
			pb += DisassembleMem32(pb);
			break;

		case 0x04: // 04h: ADD AL, imm8
		case 0x0C: // 0Ch: OR AL, imm8
		case 0x14: // 14h: ADC AL, imm8
		case 0x1C: // 1Ch: SBB AL, imm8
		case 0x24: // 24h: AND AL, imm8
		case 0x2C: // 2Ch: SUB AL, imm8
		case 0x34: // 34h: XOR AL, imm8
		case 0x3C: // 3Ch: CMP AL, imm8
		case 0x6A: // 6Ah: PUSH simm8
		case 0xA8: // A8h: TEST AL, imm8
		case 0xB0: // B0h: MOV AL, imm8
		case 0xB1: // B1h: MOV CL, imm8
		case 0xB2: // B2h: MOV DL, imm8
		case 0xB3: // B3h: MOV BL, imm8
		case 0xB4: // B4h: MOV AH, imm8
		case 0xB5: // B5h: MOV CH, imm8
		case 0xB6: // B6h: MOV DH, imm8
		case 0xB7: // B7h: MOV BH, imm8
		case 0xD4: // D4h: AAM imm8
		case 0xD5: // D5h: AAD imm8
			pb++;
			break;

		case 0x05: // 05h: ADD EAX, imm
		case 0x0D: // 0Dh: OR EAX, imm
		case 0x15: // 15h: ADC EAX, imm
		case 0x1D: // 1Dh: SBB EAX, imm
		case 0x25: // 25h: AND EAX, imm
		case 0x2D: // 2Dh: SUB EAX, imm
		case 0x35: // 35h: XOR EAX, imm
		case 0x3D: // 3Dh: CMP EAX, imm
		case 0x68: // 68h: PUSH imm
		case 0xA9: // A9h: TEST EAX, imm
		case 0xB8: // B8h: MOV EAX, imm
		case 0xB9: // B9h: MOV ECX, imm
		case 0xBA: // BAh: MOV EDX, imm
		case 0xBB: // BBh: MOV EBX, imm
		case 0xBC: // BCh: MOV ESP, imm
		case 0xBD: // BDh: MOV EBP, imm
		case 0xBE: // BEh: MOV ESI, imm
		case 0xBF: // BFh: MOV EDI, imm
			pb += cboperand;
			break;

		case 0x06: // 06h: PUSH ES
		case 0x07: // 07h: POP ES
		case 0x0E: // 0Eh: PUSH CS
		case 0x16: // 16h: PUSH SS
		case 0x17: // 17h: POP SS
		case 0x1E: // 1Eh: PUSH DS
		case 0x1F: // 1Fh: POP DS
		case 0x26: // 26h: ES:
		case 0x27: // 27h: DAA
		case 0x2E: // 2Eh: CS:
		case 0x2F: // 2Fh: DAS
		case 0x36: // 36h: SS:
		case 0x37: // 37h: AAA
		case 0x3E: // 3Eh: DS:
		case 0x3F: // 3Fh: AAS
		case 0x40: // 40h: INC EAX
		case 0x41: // 41h: INC ECX
		case 0x42: // 42h: INC EDX
		case 0x43: // 43h: INC EBX
		case 0x44: // 44h: INC ESP
		case 0x45: // 45h: INC EBP
		case 0x46: // 46h: INC ESI
		case 0x47: // 47h: INC EDI
		case 0x48: // 48h: DEC EAX
		case 0x49: // 49h: DEC ECX
		case 0x4A: // 4Ah: DEC EDX
		case 0x4B: // 4Bh: DEC EBX
		case 0x4C: // 4Ch: DEC ESP
		case 0x4D: // 4Dh: DEC EBP
		case 0x4E: // 4Eh: DEC ESI
		case 0x4F: // 4Fh: DEC EDI
		case 0x50: // 50h: PUSH EAX
		case 0x51: // 51h: PUSH ECX
		case 0x52: // 52h: PUSH EDX
		case 0x53: // 53h: PUSH EBX
		case 0x54: // 54h: PUSH ESP
		case 0x55: // 55h: PUSH EBP
		case 0x56: // 56h: PUSH ESI
		case 0x57: // 57h: PUSH EDI
		case 0x58: // 58h: POP EAX
		case 0x59: // 59h: POP ECX
		case 0x5A: // 5Ah: POP EDX
		case 0x5B: // 5Bh: POP EBX
		case 0x5C: // 5Ch: POP ESP
		case 0x5D: // 5Dh: POP EBP
		case 0x5E: // 5Eh: POP ESI
		case 0x5F: // 5Fh: POP EDI
		case 0x60: // 60h: PUSHAD
		case 0x61: // 61h: POPAD
		case 0x64: // 64h: FS:
		case 0x90: // 90h: NOP
		case 0x91: // 91h: XCHG EAX, ECX
		case 0x92: // 92h: XCHG EAX, EDX
		case 0x93: // 93h: XCHG EAX, EBX
		case 0x94: // 94h: XCHG EAX, ESP
		case 0x95: // 95h: XCHG EAX, EBP
		case 0x96: // 96h: XCHG EAX, ESI
		case 0x97: // 97h: XCHG EAX, EDI
		case 0x98: // 98h: CWDE
		case 0x99: // 99h: CDQ
		case 0x9C: // 9Ch: PUSHFD
		case 0x9D: // 9Dh: POPFD
		case 0x9E: // 9Eh: SAHF
		case 0x9F: // 9Fh: LAHF
		case 0xA4: // A4h: MOVSB
		case 0xA5: // A5h: MOVSD
		case 0xA6: // A6h: CMPSB
		case 0xA7: // A7h: CMPSD
		case 0xAA: // AAh: STOSB
		case 0xAB: // ABh: STOSD
		case 0xAC: // ACh: LODSB
		case 0xAD: // ADh: LODSD
		case 0xAE: // AEh: SCASB
		case 0xAF: // AFh: SCASD
		case 0xC9: // C9h: LEAVE
		case 0xD6: // D6h: SETALC
		case 0xD7: // D7h: XLAT
		case 0xF0: // F0h: LOCK
		case 0xF2: // F2h: REPNZ
		case 0xF3: // F3h: REP
		case 0xF5: // F5h: CMC
		case 0xF8: // F8h: CLC
		case 0xF9: // F9h: STC
		case 0xFC: // FCh: CLD
		case 0xFD: // FDh: STD
			break;

		case 0x66: // 66h: memory access size prefix
			cboperand = 2;
			continue;

		case 0x69: // 69h: IMUL reg, imm, mem
		case 0x81: // 81h: <op> mem, imm
		case 0xC7: // C7h: MOV mem, imm
			pb += DisassembleMem32(pb) + cboperand;
			break;

		case 0x6B: // 6Bh: IMUL reg8, imm8, mem8
		case 0x80: // 80h: <op> mem8, imm8
		case 0x82: // 82h: <op> mem8, simm8
		case 0x83: // 83h: <op> mem, simm8
		case 0xC0: // C0h: <op> mem8, imm8
		case 0xC1: // C1h: <op> mem, imm8
		case 0xC6: // C6h: MOV mem8, imm8
			pb += DisassembleMem32(pb) + 1;
			break;

		case 0xA0: // A0h: MOV AL, [ofs]
		case 0xA1: // A1h: MOV EAX, [ofs]
		case 0xA2: // A2h: MOV [ofs], AL
		case 0xA3: // A3h: MOV [ofs], EAX
			pb += 4;
			break;

		case 0xC8: // C8h: ENTER imm16, imm8
			pb += 3;
			break;

		case 0xF6: // F6h/0: TEST mem8, imm8; F6h/{1..7}: <op> mem8
			pb += DisassembleMem32(pb) + ((*pb & 0x38) == 0x00 ? 1 : 0);
			break;

		case 0xF7: // F7h/0: TEST mem, imm; F7h/{1..7}: <op> mem
			pb += DisassembleMem32(pb) + ((*pb & 0x38) == 0x00 ? cboperand : 0);
			break;

		case 0x0F:
			switch (*pb++)
			{
			case 0x0D: // 0Fh/0Dh: <op> mem
			case 0x18: // 0Fh/18h: <op> mem
			case 0x90: // 0Fh/90h: SETO mem8
			case 0x91: // 0Fh/91h: SETNO mem8
			case 0x92: // 0Fh/92h: SETC mem8
			case 0x93: // 0Fh/93h: SETNC mem8
			case 0x94: // 0Fh/94h: SETZ mem8
			case 0x95: // 0Fh/95h: SETNZ mem8
			case 0x96: // 0Fh/96h: SETNA mem8
			case 0x97: // 0Fh/97h: SETA mem8
			case 0x98: // 0Fh/98h: SETS mem8
			case 0x99: // 0Fh/99h: SETNS mem8
			case 0x9A: // 0Fh/9Ah: SETP mem8
			case 0x9B: // 0Fh/9Bh: SETNP mem8
			case 0x9C: // 0Fh/9Ch: SETL mem8
			case 0x9D: // 0Fh/9Dh: SETNL mem8
			case 0x9E: // 0Fh/9Eh: SETNG mem8
			case 0x9F: // 0Fh/9Fh: SETG mem8
			case 0xA3: // 0Fh/A3h: BT mem, reg
			case 0xA5: // 0Fh/A5h: SHLD mem, reg, CL
			case 0xAB: // 0Fh/ABh: BTS mem, reg
			case 0xAD: // 0Fh/ADh: SHRD mem, reg, CL
			case 0xAF: // 0Fh/AFh: IMUL reg, mem
			case 0xB3: // 0Fh/B3h: BTR mem, reg
			case 0xB4: // 0Fh/B4h: LFS reg, mem
			case 0xB5: // 0Fh/B5h: LGS reg, mem
			case 0xB6: // 0Fh/B6h: MOVZX reg, mem8
			case 0xB7: // 0Fh/B7h: MOVZX reg, mem16
			case 0xBB: // 0Fh/BBh: BTC mem, reg
			case 0xBC: // 0Fh/BCh: BSF mem, reg
			case 0xBD: // 0Fh/BDh: BSR mem, reg
			case 0xBE: // 0Fh/BEh: MOVSX reg, mem8
			case 0xBF: // 0Fh/BFh: MOVSX reg, mem16
			case 0xC0: // 0Fh/C0h: XADD mem8, reg8
			case 0xC1: // 0Fh/C1h: XADD mem, reg
			case 0xC7: // 0Fh/C7h/0: CMPXCHG8B mem
				pb += DisassembleMem32(pb);
				break;

			case 0xA0: // 0Fh/A0h: PUSH FS
			case 0xA1: // 0Fh/A1h: POP FS
			case 0xA8: // 0Fh/A8h: PUSH GS
			case 0xA9: // 0Fh/A9h: POP GS
			case 0xC8: // 0Fh/C8h: BSWAP EAX
			case 0xC9: // 0Fh/C9h: BSWAP ECX
			case 0xCA: // 0Fh/CAh: BSWAP EDX
			case 0xCB: // 0Fh/CBh: BSWAP EBX
			case 0xCC: // 0Fh/CCh: BSWAP ESP
			case 0xCD: // 0Fh/CDh: BSWAP EBP
			case 0xCE: // 0Fh/CEh: BSWAP ESI
			case 0xCF: // 0Fh/CFh: BSWAP EDI
				break;

			case 0xA4: // 0Fh/A4h: SHLD mem, reg, imm8
			case 0xAC: // 0Fh/ACh: SHRD mem, reg, imm8
			case 0xBA: // 0Fh/BAh: <op> mem, imm8
				pb += DisassembleMem32(pb) + 1;
				break;

			default:
				return 0;
			}
			break; //case 0x0F

		default:
			return 0;
		} //switch(*pb)

		cboperand = 4;
	} //for(pb)

	return (DWORD)(pb - pbCode);
} //DisassembleProlog()