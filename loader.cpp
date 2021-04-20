// Caleb Watts
// cacwatts@gmail.com

#include <iostream>
#include <fstream>
#include <cstring>
#include <elf.h>
#include <unistd.h>
#include <sys/mman.h>

#if defined(__LP64__)
#define ElfT(T) Elf64_ ## T
#else
#define ElfT(T) Elf32_ ## T
#endif

/*
TODO:
    Better (read: any) error handling
    Unmangling names of compiled C++ files
        This may not be necessary if names aren't mangled when compiling from LLVM
    Expanding what functions types can be run (as far as is possible in C++)
    Better division of functions...?
*/

// Class for processing a .o file into usable pieces of memory
class ELFParser {
private:
    char* bytes; // raw byte data
    size_t len;  // length of data; currently unused

    // all of the following are pointers into bytes
    // the only thing that is allocated on the heap here is bytes
    ElfT(Ehdr)* header;         // overall ELF header
    ElfT(Shdr)* section_table;  // table of sections
    ElfT(Shdr)* symbol_table;   // is a section, the symbols themselves are in...
    ElfT(Sym)* symbols;         // <-- ...this variable
    char* section_string_table; // cstring containing the names of all the sections
    char* string_table;         // cstring containing the names of the symbols

    // i'm not sure if there's guaranteed to be at most one of each string table,
    // though the documentation mentions that the tables can be absent

    // size (in bytes) of the section table
    int section_table_size() {
        if (header) {
            return header->e_shnum * header->e_shentsize;
        } else {
            return -1;
        }
    }

    // size (in bytes) of the symbol table
    int symbol_table_size() {
        if (symbol_table) {
            return symbol_table->sh_size;
        } else {
            return -1;
        }
    }

    // the number of symbols in the symbol table; for use with iteration
    int num_symbols() {
        return symbol_table_size() / sizeof(ElfT(Sym));
    }

    // size of the section string table in bytes; currently unused
    int section_string_table_len() {
        if (section_table) {
            return section_table[header->e_shstrndx].sh_size;
        } else {
            return -1;
        }
    }

    // index to the first non-local symbol in the symbol table
    int first_global_idx() {
        if (symbol_table) {
            return symbol_table->sh_info;
        } else {
            return -1;
        }
    }

    // finds the header and checks if it's a valid ELF file
    int load_header() {
        header = (ElfT(Ehdr)*) bytes;
        if (std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0) {
            // not an ELF file
            delete[] bytes;
            len = 0;
            throw "Trying to parse non-ELF file";
        }
        return 0;
    }

    // finds the section table
    int load_section_table() {
        if (!header) return -1;
        section_table = (ElfT(Shdr)*) (bytes + header->e_shoff);
        return 0;
    }

    // finds the symbol table
    int load_symbol_table() {
        if (!header) return -1;
        for (int i = 0; i < section_table_size(); ++i) {
            if (section_table[i].sh_type == SHT_DYNSYM || section_table[i].sh_type == SHT_SYMTAB) {
                symbol_table = section_table + i;
                break;
            }
        }
        if (!symbol_table) return -1;
        symbols = (ElfT(Sym)*) (bytes + symbol_table->sh_offset);
        return 0;
    }

    // finds the section string table
    int load_section_string_table() {
        if (!header) return -1;
        section_string_table = (char*) (bytes + section_table[header->e_shstrndx].sh_offset);
        return 0;
    }

    // finds the string table
    int load_string_table() {
        for (int i = 0; i < section_table_size(); ++i) {
            char* name = section_string_table + section_table[i].sh_name;
            if (std::strcmp(name, ".strtab") == 0) {
                string_table = (char*) (bytes + section_table[i].sh_offset);
                break;
            }
        }
        if (!string_table) return -1;
        return 0;
    }
    
    // find and return the actual symbol from the symbol table
    ElfT(Sym)* find_symbol(const std::string& fn_name) {
        if (!symbol_table || !symbols || !string_table) return NULL;
        for (int i = first_global_idx(); i < num_symbols(); ++i) {
            char* sym_name = string_table + symbols[i].st_name;
            if (strcmp(fn_name.c_str(), sym_name) == 0) {
                return symbols + i;
            }
        }
        return NULL;
    }
public:
    // constructors & deconstructors...
    ELFParser() : bytes(NULL), len(0), section_table(NULL), symbol_table(NULL), symbols(NULL),
                  section_string_table(NULL), string_table(NULL), header(NULL)
    {}


    ELFParser(std::string s) : bytes(NULL), len(0), section_table(NULL), symbol_table(NULL), symbols(NULL),
                  section_string_table(NULL), string_table(NULL), header(NULL)
    {
        load_file(s);
    }
    
    ~ELFParser() {
        if (bytes) delete[] bytes;
    }

    // load a file and prep for parsing
    int load_file(const std::string& filename) {
        std::ifstream is(filename, std::ifstream::binary);
        if (bytes) {
            delete[] bytes;
        }
        if (is) {
            is.seekg(0, is.end);
            int length = is.tellg();
            is.seekg(0, is.beg);

            bytes = new char[length];
            is.read(bytes, length);
            len = is.gcount();
            if (length != is.gcount()) {
                // do more on errors here...
                return -1;
            }
        }
        return is.gcount();
    }
    
    // run the operations to extract the info we care about
    int execute() {
        if (!bytes) return -1;
        load_header();
        load_section_table();
        load_symbol_table();
        load_section_string_table();
        load_string_table();
    }

    // print all the (non-local) symbols in the file given
    void print_symbols() {
        if (!string_table) return;
        for (int i = first_global_idx(); i < num_symbols(); ++i) {
            char* fn_name = string_table + symbols[i].st_name;
            std::cout << fn_name << std::endl;
        }
    }

    // sort of deprecated; requires the input file to be all functions of type int -> int
    void test() {
        if (!string_table) return;
        for (int i = first_global_idx(); i < num_symbols(); ++i) {
            char* fn_name = string_table + symbols[i].st_name;
            void* exec_mem = mmap(0, symbols[i].st_size, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            int offset = section_table[symbols[i].st_shndx].sh_offset + symbols[i].st_value;
            
            std::memcpy(exec_mem, bytes + offset, symbols[i].st_size);

            int (*fptr)(int) = (int(*)(int)) exec_mem;

            std::cout << fn_name << "(3) = " << fptr(3) << std::endl;
        }
    }

    // run a function of type int* -> int and return the result (or -1 and set ERRNO)
    int run(const std::string& fn_name, int* args) {
        ElfT(Sym)* symbol = find_symbol(fn_name);
        if (symbol) {
            void* exec_mem = mmap(0, symbol->st_size, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            int offset = section_table[symbol->st_shndx].sh_offset + symbol->st_value;
            std::memcpy(exec_mem, bytes + offset, symbol->st_size);
            int (*fptr)(int*) = (int(*)(int*)) exec_mem;
            return fptr(args);
        }
        errno = ENOENT;
        return -1;
    }
};

int main(int argc, char** argv) {
    int args[] = {30, 12, 28, 77, 5};
    if (argc < 2) return 1;

    std::string filename = argv[1];

    ELFParser parser = ELFParser(filename);
    parser.execute();
    // parser.print_symbols();
    // parser.test();
    int res = parser.run("multiple_args", args);
    std::cout << res << std::endl;
    return 0;
}