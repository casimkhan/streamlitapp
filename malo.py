import streamlit as st
import pefile
import lief
import capstone
import pandas as pd

# Function to analyze PE file
def analyze_pe(file_path):
    pe = pefile.PE(file_path)

    pe_info = {
        "Entry point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "Image base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "File header": {
            "Machine": hex(pe.FILE_HEADER.Machine),
            "Time date stamp": hex(pe.FILE_HEADER.TimeDateStamp),
            "Number of sections": pe.FILE_HEADER.NumberOfSections
        },
        "Optional header": {
            "Major linker version": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "Minor linker version": pe.OPTIONAL_HEADER.MinorLinkerVersion,
            # Add more optional header fields as needed
        }
    }

    # Extracting DLL information
    dlls = [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT]
    pe_info["DLLs"] = dlls
    
    sections_info = []
    for section in pe.sections:
        sections_info.append({
            "Name": section.Name.decode().strip(),
            "Virtual address": hex(section.VirtualAddress),
            "Raw size": hex(section.SizeOfRawData),
            "Entropy": section.get_entropy()
        })

    strings = extract_strings(file_path)
    code_section = pe.sections[0]
    disassembly = disassemble_code(code_section.get_data(), pe.OPTIONAL_HEADER.ImageBase)

    return pe_info, sections_info, strings, disassembly

# Function to analyze ELF file
def analyze_elf(file_path):
    elf = lief.parse(file_path)

    elf_info = {
        "Entry point": hex(elf.header.entrypoint),
        "Image base": hex(elf.optional_header.imagebase)
    }

    sections_info = []
    for section in elf.sections:
        sections_info.append({
            "Name": section.name,
            "Virtual address": hex(section.virtual_address),
            "Raw size": hex(section.size),
            "Entropy": section.entropy
        })

    strings = extract_strings(file_path)
    code_section = next((s for s in elf.sections if s.name == '.text'), None)
    if code_section:
        disassembly = disassemble_code(bytes(code_section.content), elf.header.entrypoint)
    else:
        disassembly = []

    return elf_info, sections_info, strings, disassembly

# Function to extract strings from the binary
def extract_strings(file_path):
    with open(file_path, "rb") as f:
        data = f.read()
    strings = [s.decode('latin-1') for s in data.split(b'\x00') if len(s) > 4]
    return strings

# Function to disassemble code section
def disassemble_code(code, base_address):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    disassembly = []
    for i in md.disasm(code, base_address):
        disassembly.append({
            "Address": hex(i.address),
            "Mnemonic": i.mnemonic,
            "Operands": i.op_str
        })
    return disassembly

# Function to determine file type and analyze accordingly
def analyze_file(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(4)
    if magic.startswith(b'MZ'):
        return analyze_pe(file_path)
    elif magic.startswith(b'\x7fELF'):
        return analyze_elf(file_path)
    else:
        return None, None, None, None

# Streamlit app
def main():
    st.title("Malware Analysis Tool")

    # Custom CSS for background and text colors
    st.markdown("""
        <style>
            .reportview-container {
                background: black;
                color: green;
            }
            .stMarkdown, .stTable, .stJson {
                background-color: black;
                color: green;
            }
        </style>
    """, unsafe_allow_html=True)

    uploaded_file = st.file_uploader("Choose a PE or ELF file", type=["exe", "elf", "bin"])

    if uploaded_file is not None:
        with open("temp_file", "wb") as f:
            f.write(uploaded_file.getbuffer())

        pe_info, sections_info, strings, disassembly = analyze_file("temp_file")

        if pe_info:
            st.subheader("File Information")
            st.json(pe_info)

            st.subheader("Sections Information")
            st.table(pd.DataFrame(sections_info))

            st.subheader("Extracted Strings")
            st.write(strings[:10])  # Display first 10 strings for brevity

            st.subheader("Disassembly")
            st.table(pd.DataFrame(disassembly))
        else:
            st.error("Unsupported file format")

if __name__ == "__main__":
    main()