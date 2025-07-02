import pefile


def DOS_Stub(file_path):
    try:
        pe = pefile.PE(file_path)

        print("\n")
        print("="*27 + " MS-DOS STUB " + "="*27)
        # Get DOS stub data
        dos_stub = pe.DOS_STUB
        
        if dos_stub:
            print(f"DOS Stub size:                       {len(dos_stub)} bytes")
            print(f"DOS Stub location:                   0x{pe.DOS_HEADER.sizeof():02X} - 0x{pe.DOS_HEADER.e_lfanew-1:02X}")
            
            # Try to extract readable strings from the stub
            try:
                # Look for the common "This program cannot be run in DOS mode" message
                stub_str = dos_stub.decode('ascii', errors='ignore')
                if "This program cannot be run in DOS mode" in stub_str:
                    print("DOS Stub message:                    Contains standard message")
                elif any(c.isprintable() for c in stub_str if c not in '\x00\r\n'):
                    print(f"DOS Stub contains text:              {repr(stub_str.strip())}")
                else:
                    print("DOS Stub message:                    Binary data (no readable text)")
            except:
                print("DOS Stub message:                    Binary data (no readable text)")
            
            # Show hex dump of first 64 bytes or entire stub if smaller
            print("\nDOS Stub hex dump (first 64 bytes):")
            hex_data = dos_stub[:64]
            for i in range(0, len(hex_data), 16):
                hex_line = ' '.join(f'{b:02X}' for b in hex_data[i:i+16])
                ascii_line = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in hex_data[i:i+16])
                print(f"  {i:04X}: {hex_line:<48} {ascii_line}")
            
            if len(dos_stub) > 64:
                print(f"  ... ({len(dos_stub) - 64} more bytes)")
                
        else:
            print("No DOS stub found")
        
        pe.close()
        
    except Exception as e:
        print(f"Error analyzing DOS stub: {e}")